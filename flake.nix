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
      archiveChecks = pkgs.lib.concatStringsSep "\n" (
        pkgs.lib.mapAttrsToList
          (name: spec:
            let archive = builtins.getAttr name archives;
            in ''
              test "$(stat -c %s ${archive})" = "${builtins.toString spec.size}"
              printf '%s %s %s\n' \
                '${name}' \
                '${spec.sha256}' \
                '${builtins.toString spec.size}' \
                >> "$out/fixed-output-receipts.txt"
            '')
          contract.artifacts
      );
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
          ${archiveChecks}
        '';
    };
}
