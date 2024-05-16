# comment nix
{
  description = "Random python scripts + plus something else";

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
      let pkgs = (import nixpkgs {
          config.allowUnfree = true;
          inherit system;
        }).extend overlay; 
      in
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
            prog = pkgs.stdenv.mkDerivation {
              pname = "prog";
              src = ./.;
              inherit version;
  
              nativeBuildInputs = with pkgs; [
                gcc
              ];
  
              buildPhase = ''
                mkdir build
                g++ prog/main.cpp -o build/main
              '';
  
              installPhase = ''
                mkdir -p $out/bin
                find ./build -type f \
                  -exec mv -t "$out/bin" "{}" +
              '';
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

          };
          cpp = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              gcc
            ];
          };
          pwn = pkgs.mkShell {
            packages = with pkgs; [
              # misc
              php
              curl
              git
              jdk17
              # ngrok
              docker
              docker-compose
          
              # stego
              binwalk
              stegsolve
              zsteg
              john
          
              # network
              wireshark
              tshark
              # py pyshark
          
              # web
              burpsuite
              # postman
          
              # software
              ht
              ltrace
              pwndbg
              gdb
              patchelf
              elfutils
              one_gadget
              # seccomp-tools
              ghidra
              gdb
          
              # crypto
              # sage
              z3
          
              (python3.withPackages (ps: with ps; [
                pillow
                pycryptodome
                pwntools
                ropper
                tqdm
                gmpy2
                sympy
                pip
                z3
              ]))
            ];
          
            shellHook = ''
              echo "Ready to pwn!"
            '';
          };
        };
      }
    );
}
