from azure_snapshotter.snapshotter import MetaData, MetaTable


def test_metatable():
    assert MetaData("abcde")

    meta_table = MetaTable()
    assert meta_table == {}
    assert meta_table.to_json() == "{}"
    meta_table["a"] = MetaData("foo")
    meta_table["b"] = MetaData("bar")
    assert meta_table.to_json() == '{"a": {"md5sum": "foo"}, "b": {"md5sum": "bar"}}'

    empty_table = MetaTable()
    empty_table.from_json('{"a": {"md5sum": "foo"}, "b": {"md5sum": "bar"}}')

    assert empty_table
    assert empty_table == {"a": {"md5sum": "foo"}, "b": {"md5sum": "bar"}}
