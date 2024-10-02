# comment nix
{
  description = "Random python scripts + plus something else";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";
  inputs.nixpkgs-gpu.url = "nixpkgs/nixos-24.05-small";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  
  nixConfig = {
    extra-substituters = [ "https://cuda-maintainers.cachix.org" "https://nix-community.cachix.org" ];
    extra-trusted-public-keys = [ 
      "cuda-maintainers.cachix.org-1:0dq3bujKpuEPMCX6U4WylrUDZ9JyUG0VpVZa7CNfq5E=" 
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
  };

  outputs = { self, nixpkgs, nixpkgs-gpu, flake-utils }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      overlay = final: prev: {

      };
    in

    flake-utils.lib.eachDefaultSystem (system:
      let 
        pkgs = (import nixpkgs {
          config.allowUnfree = true;
          inherit system;
        }).extend overlay; 
        pkgs-gpu = (import nixpkgs-gpu {
          config.allowUnfree = true;
          config.cudaSupport = true;
          inherit system;
        });
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
          ai = pkgs-gpu.mkShell {
            packages = [
              (pkgs-gpu.python3.withPackages (ps: with ps; [
                Keras
                opencv4
                jupyterlab
                notebook
                tqdm
                ipywidgets
              ]))
            ];
          };
        };
      }
    );
}
