from safety import is_safe_select_query, is_shell_command, zip_safe_member


def test_is_safe_select_query_allows_read_only_statements():
    assert is_safe_select_query("SELECT * FROM co_user")
    assert is_safe_select_query("SHOW TABLES")
    assert is_safe_select_query("DESCRIBE co_block")
    assert is_safe_select_query("EXPLAIN SELECT * FROM co_block")
    assert is_safe_select_query("SELECT * FROM co_user;")


def test_is_safe_select_query_blocks_mutations_and_multi_statement_input():
    assert not is_safe_select_query("DELETE FROM co_user")
    assert not is_safe_select_query("UPDATE co_user SET user = 'x'")
    assert not is_safe_select_query("DROP TABLE co_user")
    assert not is_safe_select_query("SELECT * FROM co_user; DELETE FROM co_user")
    assert not is_safe_select_query("SELECT * FROM co_user; SHOW TABLES")


def test_is_safe_select_query_blocks_comment_wrapped_abuse():
    assert not is_safe_select_query("/* hidden */ DELETE FROM co_user")
    assert not is_safe_select_query("SELECT * FROM co_user /* noop */; DROP TABLE co_user")


def test_is_shell_command_blocks_shell_tools_and_operators():
    assert is_shell_command("grep error latest.log")
    assert is_shell_command("tail -n 20 latest.log")
    assert is_shell_command("cat server.properties")
    assert is_shell_command("awk '{print $1}' file.txt")
    assert is_shell_command("sed -n '1,10p' latest.log")
    assert is_shell_command("list | grep Steve")
    assert is_shell_command("say oi && stop")
    assert is_shell_command("say oi; list")


def test_is_shell_command_allows_regular_minecraft_commands():
    assert not is_shell_command("list")
    assert not is_shell_command("say teste")
    assert not is_shell_command("tp jogador 1 64 1")


def test_zip_safe_member_accepts_normal_zip_entries():
    assert zip_safe_member("plugins/CoreProtect/config.yml")
    assert zip_safe_member("logs/")
    assert zip_safe_member("folder/subfolder/file.txt")


def test_zip_safe_member_blocks_traversal_and_absolute_paths():
    assert not zip_safe_member("../server.properties")
    assert not zip_safe_member("plugins\\..\\server.properties")
    assert not zip_safe_member("/etc/passwd")
    assert not zip_safe_member("C:\\Windows\\win.ini")
