spicy_add_analyzer(
    NAME Message
    PACKAGE_NAME Message
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
