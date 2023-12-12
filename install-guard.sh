#!/bin/sh
# This scripts downloads and installs cfn-guard latest version from github releases
# It detects platforms, downloads the pre-built binary for the latest version installs
# it in the ~/.guard/$MAJOR_VER/cfn-guard-v$MAJOR_VER-$OS_TYPE-latest/cfn-guard and symlinks ~/.guard/bin
# to the latest one

main() {
	if ! (check_cmd curl || check_cmd wget); then
		err "need 'curl' or 'wget' (command not found)"
	fi
	need_cmd awk
	need_cmd mkdir
	need_cmd rm
	need_cmd uname
	need_cmd tar
	need_cmd ln

	get_os_type
	get_arch_type
	get_latest_release |
		while
			read -r MAJOR_VER
			read -r VERSION
		do
			mkdir -p ~/.guard/"$MAJOR_VER" ~/.guard/bin ||
				err "unable to make directories ~/.guard/$MAJOR_VER, ~/.guard/bin"
			get_os_type
			download https://agithub.com/aws-cloudformation/cloudformation-guard/releases/download/"$VERSION"/cfn-guard-v"$MAJOR_VER"-"$ARCH_TYPE"-"$OS_TYPE"-latest.tar.gz >/tmp/guard.tar.gz ||
				err "unable to download https://github.com/aws-cloudformation/cloudformation-guard/releases/download/$VERSION/cfn-guard-v$MAJOR_VER-$ARCH_TYPE-$OS_TYPE-latest.tar.gz"
			tar -C ~/.guard/"$MAJOR_VER" -xzf /tmp/guard.tar.gz ||
				err "unable to untar /tmp/guard.tar.gz"
			ln -sf ~/.guard/"$MAJOR_VER"/cfn-guard-v"$MAJOR_VER"-"$ARCH_TYPE"-"$OS_TYPE"-latest/cfn-guard ~/.guard/bin ||
				err "unable to symlink to ~/.guard/bin directory"
			~/.guard/bin/cfn-guard help ||
				err "cfn-guard was not installed properly"
			echo "Remember to SET PATH include PATH=\${PATH}:~/.guard/bin"
		done
}

get_os_type() {
	_ostype="$(uname -s)"
	case "$_ostype" in
	Darwin)
		OS_TYPE="macos"
		;;

	Linux)
		# IS this RIGHT, we need to build for different ARCH as well.
		# Need more ARCH level detections
		OS_TYPE="ubuntu"
		;;

	*)
		err "unsupported OS type $_ostype"
		;;
	esac
}

get_latest_release() {
	download https://api.github.com/repos/aws-cloudformation/cloudformation-guard/releases/latest |
		awk -F '"' '/tag_name/ { print $4 }' |
		awk -F '.' '{ print $1 "\n" $0 }'
}

err() {
	echo "$1" >&2
	exit 1
}

need_cmd() {
	if ! check_cmd "$1"; then
		err "need '$1' (command not found)"
	fi
}

check_cmd() {
	command -v "$1" >/dev/null 2>&1
}

download() {
	if check_cmd curl; then
		if ! (curl -fsSL "$1"); then
			err "error attempting to download from the github repository"
		fi
	else
		if ! (wget -qO- "$1"); then
			err "error attempting to download from the github repository"
		fi
	fi
}

get_arch_type() {
	_archtype="$(uname -m)"
	case "$_archtype" in
	arm64)
		ARCH_TYPE="aarch64"
		;;
	aarch64)
		ARCH_TYPE="aarch64"
		;;
	x86_64)
		ARCH_TYPE="x86_64"
		;;

	*)
		err "unsupported architecture type $_archtype"
		;;
	esac
}

main
