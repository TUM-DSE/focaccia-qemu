{
	description = "QEMU with Focaccia plugins";

	inputs = {
		self.submodules = true;

		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		flake-utils.url = "github:numtide/flake-utils";

		berkeley-softfloat-3 = {
			url = "gitlab:qemu-project/berkeley-softfloat-3";
			flake = false;
		};

		berkeley-testfloat-3 = {
			url = "gitlab:qemu-project/berkeley-testfloat-3";
			flake = false;
		};
	};

	outputs = inputs@{
		self, 
		nixpkgs,
		flake-utils, 
		berkeley-softfloat-3,
		berkeley-testfloat-3,
		...
	}: flake-utils.lib.eachDefaultSystem (system:
	let
		pkgs = import nixpkgs { inherit system; };

		qemu-with-focaccia-plugin = pkgs.qemu.override {
			minimal = true;
			userOnly = true;
			pluginsSupport = true;
		};
	in {
		packages = rec {
			with-focaccia-plugin = qemu-with-focaccia-plugin.overrideAttrs (old: {
				pname = "qemu-focaccia";
				version = "git";
				src = self;

				postPatch = (old.postPatch or "") + ''
					rm subprojects/berkeley-softfloat-3.wrap
					cp -r ${berkeley-softfloat-3} subprojects/berkeley-softfloat-3
					chmod a+w subprojects/berkeley-softfloat-3
					cp subprojects/packagefiles/berkeley-softfloat-3/* subprojects/berkeley-softfloat-3

					rm subprojects/berkeley-testfloat-3.wrap
					cp -r ${berkeley-testfloat-3} subprojects/berkeley-testfloat-3
					chmod a+w subprojects/berkeley-testfloat-3
					cp subprojects/packagefiles/berkeley-testfloat-3/* subprojects/berkeley-testfloat-3
				'';

				postInstall = (old.postInstall or "") + ''
					mkdir -p $out/lib/plugins/
					cc -fPIC -shared ${./contrib/plugins/focaccia.c} -o $out/lib/plugins/libfocaccia.so \
					   -I$out/include/ \
					   $(pkg-config --cflags glib-2.0) \
					   $(pkg-config --libs glib-2.0)
				'';

				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.git pkgs.gdb ];
				hardeningDisable = [ "all" ];
			});

			default = with-focaccia-plugin;
		};
	});
}

