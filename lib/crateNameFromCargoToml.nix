{ fromTOML }:

{ src ? null
, cargoToml ? src + /Cargo.toml
, cargoTomlContents ? null
, ...
}:

if cargoTomlContents == null && (src == null || !builtins.pathExists cargoToml)
then
  throw ''
    unable to infer crate name and version. Please make sure the src directory
    contains a valid Cargo.toml file, or consider setting a derivation name explicitly
  ''
else
  let
    cargoTomlRealContents =
      if cargoTomlContents != null
      then cargoTomlContents
      else builtins.readFile cargoToml;

    toml = fromTOML cargoTomlRealContents;
  in
  {
    pname = toml.package.name or "cargo-package";
    version = toml.package.version or "unknown";
  }
