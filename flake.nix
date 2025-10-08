{
	description = "QEMU with Focaccia plugins";

	inputs = {
		self.submodules = true;

		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		flake-utils.url = "github:numtide/flake-utils";
	};

	outputs = {self, flake-utils, nixpkgs}: 
	flake-utils.lib.eachDefaultSystem (system:
	let
		pkgs = import nixpkgs { inherit system; };
	in {
		packages.default = pkgs.qemu.overrideAttrs (old: {
			pname = "qemu-local";
			version = "git";
			src = ./.;
			patches = [];
  			nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.git pkgs.cacert ];

			SSL_CERT_FILE   = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
			GIT_SSL_CAINFO  = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
			NIX_SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
		});
	});
}

