with import <nixpkgs> { };

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    zig
    zls
  ];
}
