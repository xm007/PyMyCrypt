import hashlib


def calculate_hash(file_path, algorithm="MD5"):
    """
    计算指定文件的哈希值。

    参数:
    file_path: 文件的路径（字符串）。
    algorithm: 使用的哈希算法（字符串），默认为"md5"。可选值为"md5"、"sha1"、"sha256"。

    返回:
    文件的哈希值（字符串）。
    """
    # 根据指定的算法初始化哈希对象
    if algorithm.lower() == "sha1":
        hash_obj = hashlib.sha1()
    elif algorithm.lower() == "sha256":
        hash_obj = hashlib.sha256()
    else:  # 默认使用md5
        hash_obj = hashlib.md5()

    # 以二进制模式打开文件，并按块更新哈希对象
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    # 返回十六进制格式的哈希值
    return hash_obj.hexdigest()


def verify_file_hash(file_path, expected_hash, algorithm="MD5"):
    """
    验证文件的哈希值是否与提供的哈希值匹配。

    参数:
    file_path: 文件的路径（字符串）。
    expected_hash: 期望的哈希值（字符串）。
    algorithm: 使用的哈希算法（字符串），默认为"md5"。

    返回:
    布尔值。如果文件的哈希值与提供的值匹配，则为True，否则为False。
    """
    # 计算文件的哈希值
    actual_hash = calculate_hash(file_path, algorithm)
    # 比较哈希值并返回比较结果
    return actual_hash.lower() == expected_hash.lower()


# # 使用示例
# file_path = 'path/to/your/file'
# algorithm = 'sha256'  # 选择算法：'md5', 'sha1', 或 'sha256'
# expected_hash = 'your_expected_hash_here'
#
# # 计算文件哈希
# print(calculate_hash(file_path, algorithm))
#
# # 验证文件哈希
# if verify_file_hash(file_path, expected_hash, algorithm):
#     print("文件验证成功，哈希值匹配。")
# else:
#     print("文件验证失败，哈希值不匹配。")
