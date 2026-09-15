{
  description = "AxiomLayer fixed-output integration for managed CPython";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/c3eea5b2156db11c7eeeada3dc737711255b253e";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      contract = builtins.fromJSON (builtins.readFile ./axiomlayer/managed-python.json);
      policy = ./axiomlayer/dotfiles/upstream-promotion-policy.json;
      runtimeManifest = ./axiomlayer/dotfiles/runtime-foundation.json;
      candidate = ./axiomlayer/dotfiles/candidate.json;
      archives = builtins.mapAttrs (_: spec: pkgs.fetchurl {
        url = spec.upstreamUrl;
        hash = spec.nixHash;
      }) contract.artifacts;
      allArchives = pkgs.lib.concatStringsSep " " (builtins.attrValues archives);
    in {
      checks.${system}.axiomlayer-managed-python = pkgs.runCommand
        "axiomlayer-managed-python-${contract.source.version}-${contract.source.build}"
        {
          nativeBuildInputs = [ pkgs.python3 ];
        }
        ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME" "$out"
          python ${self}/axiomlayer/verify_managed_python.py contract \
            --repository-root ${self} \
            --policy ${policy} \
            --runtime-manifest ${runtimeManifest} \
            --candidate ${candidate} \
            > "$out/contract-receipt.json"
          for archive in ${allArchives}; do
            test -s "$archive"
          done
          python ${self}/axiomlayer/verify_managed_python.py artifact \
            --platform linux-x86_64 \
            --archive ${archives."linux-x86_64"} \
            > "$out/linux-x86_64-receipt.json"
        '';
    };
}
