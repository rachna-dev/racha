# What this environment may do. Nothing here is implied:
# an empty allowlist denies all network, and deleting a line
# makes the environment stricter rather than looser.
#
# NOTE: flat for now. `19` §2.2's `isolation = { … }` nesting
# needs the NixOS-style module that does the flattening, which
# is not built yet.
{
  tier = "allowlist";
  profile = "development";
  network.allow = [ ];
}
