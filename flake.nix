{
  description = "nox — declarative Linux installer TUI (produces LIS, applies NixOS)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { nixpkgs, flake-utils, disko, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        nox = pkgs.callPackage ./package.nix {
          disko = disko.packages.${system}.disko;
        };

        # Fully static, self-contained binary for releases: pcsclite linked
        # statically, no disko wrapper (single portable file). The static
        # pcsclite build fails to populate its doc/man outputs, so drop them.
        nox-static = pkgs.pkgsStatic.callPackage ./package.nix {
          wrapDisko = false;
          pcsclite = pkgs.pkgsStatic.pcsclite.overrideAttrs (old: {
            outputs = builtins.filter (o: o != "doc" && o != "man") old.outputs;
          });
        };
      in
      {
        packages = {
          inherit nox nox-static;
          default = nox;
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.cmake
          ];
          buildInputs = [ pkgs.pcsclite ];

          packages = [
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer
            pkgs.git-cliff
          ];

          # So `cargo run` finds libpcsclite.so at runtime outside a nix build.
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.pcsclite ];
        };
      }
    );
}
