#!/bin/sh
set -u
ACME=/usr/lib/acme/client/acme.sh
LOG_TAG=acme-acmesh
NOTIFY=/usr/lib/acme/notify

# shellcheck source=net/acme/files/functions.sh
. /usr/lib/acme/functions.sh

# Needed by acme.sh
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export NO_TIMESTAMP=1

link_certs() {
	local main_domain
	local domain_dir
	domain_dir="$1"
	main_domain="$2"

	(
		umask 077
		cat "$domain_dir/fullchain.cer" "$domain_dir/$main_domain.key" >"$domain_dir/combined.cer"
	)

	if [ ! -e "$CERT_DIR/$main_domain.crt" ]; then
		ln -s "$domain_dir/$main_domain.cer" "$CERT_DIR/$main_domain.crt"
	fi
	if [ ! -e "$CERT_DIR/$main_domain.key" ]; then
		ln -s "$domain_dir/$main_domain.key" "$CERT_DIR/$main_domain.key"
	fi
	if [ ! -e "$CERT_DIR/$main_domain.fullchain.crt" ]; then
		ln -s "$domain_dir/fullchain.cer" "$CERT_DIR/$main_domain.fullchain.crt"
	fi
	if [ ! -e "$CERT_DIR/$main_domain.combined.crt" ]; then
		ln -s "$domain_dir/combined.cer" "$CERT_DIR/$main_domain.combined.crt"
	fi
	if [ ! -e "$CERT_DIR/$main_domain.chain.crt" ]; then
		ln -s "$domain_dir/ca.cer" "$CERT_DIR/$main_domain.chain.crt"
	fi
}

case $1 in
get)
	set --
	[ "$debug" = 1 ] && set -- "$@" --debug

	case $key_type in
	ec*)
		keylength=${key_type/ec/ec-}
		domain_dir="$state_dir/${main_domain}_ecc"
		set -- "$@" --ecc
		;;
	rsa*)
		keylength=${key_type#rsa}
		domain_dir="$state_dir/$main_domain"
		;;
	esac

	log info "Running ACME for $main_domain with validation_method $validation_method"

	if [ -e "$domain_dir" ]; then
		if [ "$staging" = 0 ] && grep -q "acme-staging" "$domain_dir/$main_domain.conf"; then
			mv "$domain_dir" "$domain_dir.staging"
			log info "Certificates are previously issued from a staging server, but staging option is disabled, moved to $domain_dir.staging."
			staging_moved=1
		else
			set -- "$@" --renew --home "$state_dir" -d "$main_domain"
			log info "$ACME $*"
			trap '$NOTIFY renew-failed;exit 1' INT
			$ACME "$@"
			status=$?
			trap - INT

			case $status in
			0)
				link_certs "$domain_dir" "$main_domain"
				$NOTIFY renewed
				exit
				;;
			2)
				# renew skipped, ignore.
				exit
				;;
			*)
				$NOTIFY renew-failed
				exit 1
				;;
			esac
		fi
	fi

	for d in $domains; do
		set -- "$@" -d "$d"
	done
	set -- "$@" --keylength "$keylength" --accountemail "$account_email"

	if [ "$acme_server" ]; then
		set -- "$@" --server "$acme_server"
	# default to letsencrypt because the upstream default may change
	elif [ "$staging" = 1 ]; then
		set -- "$@" --server letsencrypt_test
	else
		set -- "$@" --server letsencrypt
	fi

	if [ "$days" ]; then
		set -- "$@" --days "$days"
	fi

	case "$validation_method" in
	"dns")
		set -- "$@" --dns "$dns"
		if [ "$dalias" ]; then
			set -- "$@" --domain-alias "$dalias"
			if [ "$calias" ]; then
				log err "Both domain and challenge aliases are defined. Ignoring the challenge alias."
			fi
		elif [ "$calias" ]; then
			set -- "$@" --challenge-alias "$calias"
		fi
		if [ "$dns_wait" ]; then
			set -- "$@" --dnssleep "$dns_wait"
		fi
		;;
	"standalone")
		set -- "$@" --standalone --listen-v6
		;;
	"nginx")
		# 使用 acme.sh 的 --nginx 模式，自动在 nginx 中临时下发 http-01
		# 这里做一个最基本的存在性检查，避免误选
		if command -v nginx >/dev/null 2>&1; then
			set -- "$@" --nginx
		else
			log err "validation_method set to 'nginx' but nginx binary not found in PATH"
			exit 1
		fi
		;;
	"apache")
		# 使用 acme.sh 的 --apache 模式，自动在 Apache(httpd) 中临时下发 http-01
		# 通常系统会提供 apachectl 或 httpd 其中之一
		if command -v apachectl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
			set -- "$@" --apache
		else
			log err "validation_method set to 'apache' but no apachectl/httpd found in PATH"
			exit 1
		fi
		;;
	"webroot")
		# 明确拒绝旧的 webroot 模式，避免误用导致签发失败
		# 如需继续使用，请改为 validation_method='nginx' 或 'apache'
		log err "validation_method 'webroot' is deprecated. Use 'nginx' or 'apache' instead."
		exit 1
		;;
	*)
		log err "Unsupported validation_method $validation_method"
		;;
		exit 1
		;;
	esac

	set -- "$@" --issue --home "$state_dir"

	log info "$ACME $*"
	trap '$NOTIFY issue-failed;exit 1' INT
	"$ACME" "$@" \
		--pre-hook "$NOTIFY prepare" \
		--renew-hook "$NOTIFY renewed"
	status=$?
	trap - INT

	case $status in
	0)
		link_certs "$domain_dir" "$main_domain"
		$NOTIFY issued
		;;
	*)
		if [ "$staging_moved" = 1 ]; then
			mv "$domain_dir.staging" "$domain_dir"
			log err "Staging certificate restored"
		elif [ -d "$domain_dir" ]; then
			failed_dir="$domain_dir.failed-$(date +%s)"
			mv "$domain_dir" "$failed_dir"
			log err "State moved to $failed_dir"
		fi
		$NOTIFY issue-failed
		;;
	esac
	;;
esac
