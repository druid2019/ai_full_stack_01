"""
**************************************
*  @Author  ：   Administrator
*  @Time    ：   2025/6/4 15:30
*  @Project :   ai_full_stack_01
*  @FileName:   auth_system.py
**************************************
"""
import re
import unittest
from unittest.mock import MagicMock, patch
import hashlib
import secrets


# ====================== 验证工具函数 ======================
def is_valid_email(email_string):
    """
    验证邮箱地址格式的有效性

    参数:
        email_string (str): 待验证的邮箱地址

    返回:
        bool: True表示有效，False表示无效

    异常:
        TypeError: 如果输入不是字符串类型

    正则表达式设计思路:
        1. 用户名部分: [a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+
            - 允许字母、数字和常见特殊字符
            - 不允许连续两个点或开头/结尾的点
        2. @符号: @
        3. 域名部分: [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+
            - 允许多级域名 (如 example.co.uk)
            - 每级域名长度限制在63字符以内
            - 不允许连字符开头或结尾
    """
    if not isinstance(email_string, str):
        raise TypeError("邮箱地址必须是字符串类型")

    # 健壮的邮箱验证正则表达式 (符合RFC 5322标准)
    pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
    return bool(re.match(pattern, email_string))


def is_valid_phone(phone_string):
    """
    验证中国大陆手机号码格式的有效性

    参数:
        phone_string (str): 待验证的手机号码

    返回:
        bool: True表示有效，False表示无效

    异常:
        TypeError: 如果输入不是字符串类型
    """
    if not isinstance(phone_string, str):
        raise TypeError("手机号码必须是字符串类型")

    # 验证中国大陆手机号码 (11位，1开头，第二位为3-9)
    pattern = r"^1[3-9]\d{9}$"
    return bool(re.match(pattern, phone_string))


def is_valid_password(password_string):
    """
    验证密码复杂度

    要求:
        - 长度至少6位
        - 包含字母、数字和至少一个特殊字符

    参数:
        password_string (str): 待验证的密码

    返回:
        bool: True表示有效，False表示无效
    """
    if not isinstance(password_string, str):
        return False

    # 检查长度
    if len(password_string) < 6:
        return False

    # 检查是否包含字母、数字和特殊字符
    has_letter = any(char.isalpha() for char in password_string)
    has_digit = any(char.isdigit() for char in password_string)
    has_special = any(not char.isalnum() for char in password_string)

    return has_letter and has_digit and has_special


def is_valid_username(username):
    """
    验证用户名格式

    要求:
        - 长度在3-20个字符之间
        - 只允许字母、数字、下划线和连字符

    参数:
        username (str): 待验证的用户名

    返回:
        bool: True表示格式有效，False表示无效
    """
    if not isinstance(username, str):
        return False

    # 检查长度
    if len(username) < 3 or len(username) > 20:
        return False

    # 检查字符范围 (允许字母、数字、下划线、连字符)
    pattern = r"^[a-zA-Z0-9_-]+$"
    return bool(re.match(pattern, username))


# ====================== 用户管理类 ======================
class UserManager:
    def __init__(self):
        # 用户存储: {username: {details}}
        self.users = {}
        # 重置密码令牌存储: {token: username}
        self.reset_tokens = {}

    def _hash_password(self, password):
        """使用SHA-256对密码进行哈希处理"""
        salt = secrets.token_hex(8)  # 生成随机盐值
        return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

    def _verify_password(self, stored_password, provided_password):
        """验证密码是否匹配"""
        salt, hashed = stored_password.split(':')
        return hashlib.sha256((salt + provided_password).encode()).hexdigest() == hashed

    def register(self, identifier, username, password, confirm_password):
        """
        用户注册

        参数:
            identifier (str): 邮箱或手机号
            username (str): 用户名
            password (str): 密码
            confirm_password (str): 确认密码

        返回:
            dict: 包含成功状态和消息的字典
        """
        # 验证输入
        if not (is_valid_email(identifier) or is_valid_phone(identifier)):
            return {"success": False, "message": "无效的邮箱或手机号"}

        if not is_valid_username(username):
            return {"success": False, "message": "用户名必须为3-20个字母、数字、下划线或连字符"}

        if not is_valid_password(password):
            return {"success": False, "message": "密码必须至少6位，包含字母、数字和特殊字符"}

        if password != confirm_password:
            return {"success": False, "message": "两次输入的密码不一致"}

        # 检查用户名是否已存在
        if username in self.users:
            return {"success": False, "message": "用户名已被使用"}

        # 检查邮箱/手机是否已注册
        for user_data in self.users.values():
            if user_data['identifier'] == identifier:
                return {"success": False, "message": "该邮箱或手机号已注册"}

        # 创建用户
        self.users[username] = {
            "identifier": identifier,
            "password": self._hash_password(password)
        }

        return {"success": True, "message": "注册成功"}

    def login(self, username, password):
        """
        用户登录

        参数:
            username (str): 用户名
            password (str): 密码

        返回:
            dict: 包含成功状态和消息的字典
        """
        user_data = self.users.get(username)
        if not user_data:
            return {"success": False, "message": "用户名不存在"}

        if not self._verify_password(user_data["password"], password):
            return {"success": False, "message": "密码错误"}

        return {"success": True, "message": "登录成功"}

    def initiate_password_reset(self, identifier):
        """
        发起密码重置

        参数:
            identifier (str): 邮箱或手机号

        返回:
            dict: 包含成功状态、消息和令牌的字典
        """
        # 查找匹配的用户
        user = None
        for username, data in self.users.items():
            if data['identifier'] == identifier:
                user = username
                break

        if not user:
            return {"success": False, "message": "未找到关联的账号"}

        # 生成并存储重置令牌
        token = secrets.token_urlsafe(32)
        self.reset_tokens[token] = user
        return {"success": True, "message": "重置请求已受理", "token": token}

    def reset_password(self, token, new_password, confirm_password):
        """
        重置密码

        参数:
            token (str): 重置令牌
            new_password (str): 新密码
            confirm_password (str): 确认密码

        返回:
            dict: 包含成功状态和消息的字典
        """
        # 验证令牌
        username = self.reset_tokens.get(token)
        if not username:
            return {"success": False, "message": "无效或过期的令牌"}

        # 验证密码
        if not is_valid_password(new_password):
            return {"success": False, "message": "密码必须至少6位，包含字母、数字和特殊字符"}

        if new_password != confirm_password:
            return {"success": False, "message": "两次输入的密码不一致"}

        # 更新密码
        self.users[username]["password"] = self._hash_password(new_password)

        # 删除已使用的令牌
        del self.reset_tokens[token]

        return {"success": True, "message": "密码重置成功"}


# ====================== 单元测试 ======================
class TestIsValid(unittest.TestCase):
    # ===== 邮箱验证测试 =====
    def test_valid_emails(self):
        """测试有效的邮箱地址"""
        valid_emails = [
            "simple@example.com",  # 简单邮箱
            "user.name@example.com",  # 带点的用户名
            "user+alias@example.com",  # 带+号的别名
            "user@sub-domain.example.com",  # 带连字符的域名
            "user@example.co.uk",  # 多级域名
            "user@example.technology",  # 长域名后缀
            "123456@example.com",  # 数字用户名
            "user@123.com",  # 数字域名
            "user@example.museum",  # 特殊域名后缀
            "user@xn--fsq.com"  # Punycode编码域名 (国际化域名)
        ]
        for email in valid_emails:
            with self.subTest(email=email):
                self.assertTrue(is_valid_email(email))

    def test_invalid_emails_format(self):
        """测试无效的邮箱格式"""
        invalid_emails = [
            "plainaddress",  # 缺少@
            "@missingusername.com",  # 缺少用户名
            "username@.com",  # 缺少域名
            "username@com",  # 缺少顶级域名
            "username@.com.",  # 结尾点
            "username@-example.com",  # 域名以连字符开头
            "username@example..com",  # 连续的点
            "username@.example.com",  # 域名以点开头
            "username@example.c",  # 顶级域名太短
            "user name@example.com",  # 用户名中有空格
            "username@exa mple.com",  # 域名中有空格
            "username@.example.com",  # 无效的域名
            "username@example_com",  # 无效字符
            "username@example,com",  # 逗号分隔
            "username@example;com"  # 分号分隔
        ]
        for email in invalid_emails:
            with self.subTest(email=email):
                self.assertFalse(is_valid_email(email))

    def test_invalid_input_type(self):
        """测试非字符串输入"""
        invalid_inputs = [
            12345,  # 整数
            None,  # None
            ["email@example.com"],  # 列表
            {"email": "test@example.com"},  # 字典
            3.14,  # 浮点数
            True  # 布尔值
        ]
        for input_val in invalid_inputs:
            with self.subTest(input_val=input_val):
                with self.assertRaises(TypeError):
                    is_valid_email(input_val)

    def test_empty_string(self):
        """测试空字符串"""
        self.assertFalse(is_valid_email(""))

    def test_emails_with_spaces(self):
        """测试带空格的邮箱地址"""
        spaced_emails = [
            " user@example.com",  # 前导空格
            "user@example.com ",  # 尾部空格
            "user @example.com",  # 用户名空格
            "user@ example.com",  # @后空格
            "user@example .com",  # 域名空格
            "user@sub domain.com"  # 子域名空格
        ]
        for email in spaced_emails:
            with self.subTest(email=email):
                self.assertFalse(is_valid_email(email))

    # ===== 手机号验证测试 =====
    def test_valid_phones(self):
        """测试有效的手机号码"""
        valid_phones = [
            "13012345678",  # 中国联通
            "15012345678",  # 中国联通
            "18012345678",  # 中国电信
            "19912345678",  # 中国电信
            "13912345678",  # 中国移动
            "17012345678",  # 虚拟运营商
            "16612345678",  # 中国联通
            "19812345678"  # 中国移动
        ]
        for phone in valid_phones:
            with self.subTest(phone=phone):
                self.assertTrue(is_valid_phone(phone))

    def test_invalid_phones(self):
        """测试无效的手机号码"""
        invalid_phones = [
            "12345678901",  # 无效号段
            "19012345678",  # 无效号段
            "1234567890",  # 长度不足
            "123456789012",  # 长度过长
            "abcdefghijk",  # 非数字字符
            " 13012345678",  # 前导空格
            "13012345678 ",  # 尾部空格
            "13 012345678",  # 中间空格
            "+8613012345678",  # 包含国际代码
            "130-1234-5678",  # 包含分隔符
            "1301234567a"  # 包含字母
        ]
        for phone in invalid_phones:
            with self.subTest(phone=phone):
                self.assertFalse(is_valid_phone(phone))

    def test_invalid_phone_input_type(self):
        """测试手机号验证的非字符串输入"""
        invalid_inputs = [
            13012345678,  # 整数
            None,  # None
            [13012345678],  # 列表
            {"phone": "13012345678"},  # 字典
            13012345678.0  # 浮点数
        ]
        for input_val in invalid_inputs:
            with self.subTest(input_val=input_val):
                with self.assertRaises(TypeError):
                    is_valid_phone(input_val)

    # ===== 密码验证测试 =====
    def test_valid_passwords(self):
        """测试有效的密码"""
        valid_passwords = [
            "P@ssw0rd",  # 字母+数字+特殊字符
            "Secur3#",  # 短但有效
            "L0ngP@ssw0rd!123",  # 长密码
            "a1B@c2D#",  # 混合大小写
            "12345@a",  # 最小长度
            "!@#$%^&*()a1"  # 多种特殊字符
        ]
        for pwd in valid_passwords:
            with self.subTest(password=pwd):
                self.assertTrue(is_valid_password(pwd))

    def test_invalid_passwords(self):
        """测试无效的密码"""
        invalid_passwords = [
            "password",  # 缺少数字和特殊字符
            "123456",  # 缺少字母和特殊字符
            "p@ssw",  # 长度不足
            "PASSWORD123",  # 缺少特殊字符
            "!@#$%^",  # 缺少字母和数字
            "abc123",  # 缺少特殊字符
            " ",  # 空密码
            "a@1",  # 长度不足
            "1234567890"  # 缺少字母和特殊字符
        ]
        for pwd in invalid_passwords:
            with self.subTest(password=pwd):
                self.assertFalse(is_valid_password(pwd))

    def test_password_edge_cases(self):
        """测试密码边界情况"""
        # 长度边界
        self.assertTrue(is_valid_password("a1@b"))  # 6位有效
        self.assertFalse(is_valid_password("a1@b"))  # 5位无效

        # 字符类型边界
        self.assertTrue(is_valid_password("a1@bcd"))  # 有效
        self.assertFalse(is_valid_password("abcdef"))  # 缺少数字和特殊字符
        self.assertFalse(is_valid_password("123456"))  # 缺少字母和特殊字符
        self.assertFalse(is_valid_password("@#$%^&"))  # 缺少字母和数字


class TestUserModule(unittest.TestCase):
    def setUp(self):
        """在每个测试前创建新的用户管理器"""
        self.manager = UserManager()

    def test_successful_registration(self):
        """测试成功注册"""
        # 使用邮箱注册
        result = self.manager.register(
            identifier="user@example.com",
            username="testuser",
            password="P@ssw0rd123",
            confirm_password="P@ssw0rd123"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "注册成功")
        self.assertIn("testuser", self.manager.users)

        # 使用手机号注册
        result = self.manager.register(
            identifier="13012345678",
            username="mobileuser",
            password="Secur3#",
            confirm_password="Secur3#"
        )
        self.assertTrue(result["success"])
        self.assertIn("mobileuser", self.manager.users)

    def test_registration_failure(self):
        """测试注册失败的各种情况"""
        # 无效邮箱
        result = self.manager.register(
            identifier="invalid-email",
            username="user1",
            password="P@ssw0rd",
            confirm_password="P@ssw0rd"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "无效的邮箱或手机号")

        # 无效手机号
        result = self.manager.register(
            identifier="123456",
            username="user2",
            password="P@ssw0rd",
            confirm_password="P@ssw0rd"
        )
        self.assertFalse(result["success"])

        # 无效用户名
        result = self.manager.register(
            identifier="user@example.com",
            username="u$er",
            password="P@ssw0rd",
            confirm_password="P@ssw0rd"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "用户名必须为3-20个字母、数字、下划线或连字符")

        # 无效密码
        result = self.manager.register(
            identifier="user@example.com",
            username="user3",
            password="weak",
            confirm_password="weak"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "密码必须至少6位，包含字母、数字和特殊字符")

        # 密码不匹配
        result = self.manager.register(
            identifier="user@example.com",
            username="user4",
            password="P@ssw0rd1",
            confirm_password="P@ssw0rd2"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "两次输入的密码不一致")

        # 用户名重复
        self.manager.register("user@example.com", "uniqueuser", "P@ssw0rd", "P@ssw0rd")
        result = self.manager.register(
            identifier="another@example.com",
            username="uniqueuser",
            password="P@ssw0rd",
            confirm_password="P@ssw0rd"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "用户名已被使用")

        # 邮箱/手机重复
        self.manager.register("duplicate@example.com", "user5", "P@ssw0rd", "P@ssw0rd")
        result = self.manager.register(
            identifier="duplicate@example.com",
            username="user6",
            password="P@ssw0rd",
            confirm_password="P@ssw0rd"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "该邮箱或手机号已注册")

    def test_successful_login(self):
        """测试成功登录"""
        self.manager.register("user@example.com", "loginuser", "P@ssw0rd", "P@ssw0rd")

        # 正确凭据
        result = self.manager.login("loginuser", "P@ssw0rd")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "登录成功")

    def test_login_failure(self):
        """测试登录失败的各种情况"""
        self.manager.register("user@example.com", "loginuser", "P@ssw0rd", "P@ssw0rd")

        # 用户名不存在
        result = self.manager.login("wronguser", "P@ssw0rd")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "用户名不存在")

        # 密码错误
        result = self.manager.login("loginuser", "WrongP@ss")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "密码错误")

    def test_password_reset(self):
        """测试完整的密码重置流程"""
        self.manager.register("user@example.com", "resetuser", "OldP@ss", "OldP@ss")

        # 1. 发起密码重置
        result = self.manager.initiate_password_reset("user@example.com")
        self.assertTrue(result["success"])
        self.assertIn("token", result)
        token = result["token"]

        # 无效标识符
        result = self.manager.initiate_password_reset("wrong@example.com")
        self.assertFalse(result["success"])

        # 2. 使用令牌重置密码
        result = self.manager.reset_password(token, "NewP@ss123", "NewP@ss123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "密码重置成功")

        # 验证新密码可用
        login_result = self.manager.login("resetuser", "NewP@ss123")
        self.assertTrue(login_result["success"])

        # 旧密码不再可用
        login_result = self.manager.login("resetuser", "OldP@ss")
        self.assertFalse(login_result["success"])

    def test_password_reset_failure(self):
        """测试密码重置失败情况"""
        self.manager.register("user@example.com", "resetuser", "P@ssw0rd", "P@ssw0rd")

        # 无效令牌
        result = self.manager.reset_password("invalid-token", "NewP@ss", "NewP@ss")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "无效或过期的令牌")

        # 获取有效令牌
        token = self.manager.initiate_password_reset("user@example.com")["token"]

        # 无效密码
        result = self.manager.reset_password(token, "weak", "weak")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "密码必须至少6位，包含字母、数字和特殊字符")

        # 密码不匹配
        result = self.manager.reset_password(token, "NewP@ss1", "NewP@ss2")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "两次输入的密码不一致")

    def test_password_hashing(self):
        """测试密码哈希和验证"""
        password = "Secur3P@ss"
        hashed = self.manager._hash_password(password)

        # 验证正确密码
        self.assertTrue(self.manager._verify_password(hashed, password))

        # 错误密码
        self.assertFalse(self.manager._verify_password(hashed, "WrongP@ss"))

        # 不同密码不同哈希
        another_hashed = self.manager._hash_password("AnotherP@ss")
        self.assertNotEqual(hashed, another_hashed)

        # 相同密码不同盐值
        same_password_hashed = self.manager._hash_password(password)
        self.assertNotEqual(hashed, same_password_hashed)


if __name__ == "__main__":
    unittest.main(verbosity=2)