{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      eachSystems =
        f: lib.genAttrs lib.systems.flakeExposed (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      devShells = eachSystems (
        system: pkgs: rec {
          without-rust = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.dwarfs
              pkgs.fakeroot
            ];
          };
        }
      );
    };
}
