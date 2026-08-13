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

      mk-focaccia-qemu = { pname, regressionPatch ? null }:
        qemu-with-focaccia-plugin.overrideAttrs (old: {
          inherit pname;
          version = "9.2.92";
          src = self;
          patches = (old.patches or [])
            ++ pkgs.lib.optional (regressionPatch != null) regressionPatch;

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
            cc -fPIC -shared ${./contrib/plugins/focaccia.c} \
              -o $out/lib/plugins/libfocaccia.so \
              -I$out/include/ \
              $(pkg-config --cflags glib-2.0) \
              $(pkg-config --libs glib-2.0)
          '';

          nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.git pkgs.gdb ];
          hardeningDisable = [ "all" ];

          passthru = (old.passthru or {}) // {
            focacciaPluginProtocol = 2;
            issue2248Injected = regressionPatch != null;
          };
        });
      referenceQemu = mk-focaccia-qemu {
        pname = "qemu-focaccia";
      };
      injectedQemu = mk-focaccia-qemu {
        pname = "qemu-focaccia-2248-injected";
        regressionPatch = ./issue-2248.patch;
      };
    in {
      packages = {
        # Preserve the existing package as the fixed/reference optimizer build.
        with-focaccia-plugin = referenceQemu;

        # Dedicated regression-injected package used only by the #2248 case.
        with-focaccia-plugin-2248 = injectedQemu;

        plugin-source = pkgs.runCommand "focaccia-qemu-plugin-source" { } ''
          mkdir -p "$out/contrib/plugins"
          cp ${./contrib/plugins/focaccia.c} "$out/contrib/plugins/focaccia.c"
        '';

        default = referenceQemu;
      };

      checks = pkgs.lib.optionalAttrs (system == "aarch64-linux") {
        issue-2248-optimizer-fidelity = pkgs.runCommand
          "issue-2248-optimizer-fidelity"
          { nativeBuildInputs = [ pkgs.gcc ]; }
          ''
            cc -O2 ${./tests/tcg/aarch64/test-2248.c} -o test-2248

            ulimit -c 0
            set +e
            ${injectedQemu}/bin/qemu-aarch64 ./test-2248
            injected_status=$?
            set -e
            if [ "$injected_status" -eq 0 ]; then
              echo "Regression-injected QEMU accepted issue-2248" >&2
              exit 1
            fi

            ${referenceQemu}/bin/qemu-aarch64 ./test-2248
            touch "$out"
          '';
      };
    });
}
