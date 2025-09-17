rule Pickle_Magic_Proto {
  meta:
    description = "Detects pickle stream magic and protocol byte"
  strings:
    $magic = { 80 0? } // 0x80 followed by protocol version byte
  condition:
    $magic at 0
}

rule Pickle_Dangerous_Globals {
  meta:
    description = "Detects suspicious GLOBAL targets commonly used for RCE"
  strings:
    $builtins = "builtins" nocase ascii
    $os_system = "os\nsystem\n" ascii
    $posix_system = "posix\nsystem\n" ascii
    $subprocess_popen = "subprocess\nPopen\n" ascii
    $eval = "eval" ascii
    $exec = "exec" ascii
  condition:
    any of them
}
