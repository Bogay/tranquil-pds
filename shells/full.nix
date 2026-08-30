{
  mkShell,
  callPackage,
  writeShellApplication,

  postgresql,
  garage_2,
  coreutils,
  gnugrep,
  gawk,
}:
let
  devServices = writeShellApplication {
    name = "tranquil-dev-services";
    runtimeInputs = [
      postgresql
      garage_2
      coreutils
      gnugrep
      gawk
    ];
    text = builtins.readFile ./full-services.sh;
  };
in
mkShell {
  inputsFrom = [ (callPackage ../shell.nix { }) ];

  packages = [
    devServices
    postgresql
    garage_2
  ];
}
