{ lib
, cmake
, disko ? null
, makeWrapper
, pkg-config
, pcsclite
, rustPlatform
  # Wrap the binary so `disko` is on PATH. Off for the standalone/static release
  # binary, which must remain a single self-contained file.
, wrapDisko ? true
}:

rustPlatform.buildRustPackage {
  pname = "nox";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      !(type == "directory" && base == "target");
  };

  cargoLock.lockFile = ./Cargo.lock;
  # The lis-spec dependency comes from git (github:onix-os/lis).
  cargoLock.allowBuiltinFetchGit = true;

  # YubiKey is always built in; pcsclite is linked so native SOPS/age decryption
  # works in the shipped binary. A static build links pcsclite statically.
  nativeBuildInputs = [
    cmake
    pkg-config
  ] ++ lib.optional wrapDisko makeWrapper;

  buildInputs = [
    pcsclite
  ];

  postInstall = lib.optionalString wrapDisko ''
    wrapProgram $out/bin/nox \
      --prefix PATH : ${lib.makeBinPath [ disko ]}
  '';
}
