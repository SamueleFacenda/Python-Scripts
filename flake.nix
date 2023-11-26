{
  description = "An full-optional python flake template";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      overlay = final: prev: {

      };
    in

    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = (nixpkgs.legacyPackages.${system}.extend overlay); in
      {

        packages = rec {
            default = fitet-parser;
            fitet-parser = pkgs.python3.pkgs.buildPythonApplication {
              pname = "fitet-parser";
              src = ./.;
              inherit version;
              pyproject = true;
              #format = "pyproject";

              propagatedBuildInputs = with pkgs.python3.pkgs; [
                beautifulsoup4
                requests
                icecream
                sqlalchemy
              ];

              nativeBuildInputs = with pkgs; [
                python3.pkgs.setuptools
              ];

            };
          };
          
        apps = {
            default = {
              type = "app";
              program = "${self.packages.${system}.default}/bin/fitet-runner";
            };
          };

        devShells = {
          default = pkgs.mkShell {
            packages = with pkgs; [
              php
              (python3.withPackages (ps: with ps; [
                beautifulsoup4
                requests
                icecream
                pillow
                tqdm
                pandas
                pyautogui
                keyboard
                sqlalchemy
              ]))
            ];

            #shellHook = ''
            #  exec zsh
            #'';

          };

        };
      }
    );
}
