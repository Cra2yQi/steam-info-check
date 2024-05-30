import poplib
import re
import logging
import time
from email.parser import Parser
from email.header import decode_header
from email.utils import parseaddr
from datetime import datetime

'''
从邮箱中正则验证码，并清空邮箱
'''

def fetch_latest_email_token(email, password, pop_server):
    pop_server = pop_server.split(":")
    # 尝试连接到POP3服务器
    try:
        if pop_server[1] == '110':
            server = poplib.POP3(pop_server[0], int(pop_server[1]))
        else:
            # 测试微软需要SSL
            server = poplib.POP3_SSL(pop_server[0], 995)
        server.user(email)
        server.pass_(password)
    except poplib.error_proto as e:
        logging.error("登录邮件服务器失败：{}".format(e))
        return None
    try:
        # 检索邮件数量
        mail_count, _ = server.stat()
        if mail_count == 0:
            logging.info("邮箱中没有邮件。")
            return None
        for i in range(mail_count, 0, -1):
            # 获取并解析最新一封邮件
            _, lines, _ = server.retr(i)  # 获取最后一封邮件
            msg_content = b"\r\n".join(lines)  # 解码邮件内容
            # 使用正则表达式查找特定格式的字符串（例如，5位数字或字母）
            match = re.findall(
                r"\\r\\n=09=09=09=09=09=09=09=09=09=09=09=09([\w]{5})=09=09=09=09=09=09=09=09=09=09=09<=\\r\\n",
                str(msg_content))
            if len(match):
                token = match[0]
                return token
        return None
    except Exception as e:
        logging.error(f"处理邮件时发生错误：{e}")
        return None
    finally:
        for i in range(mail_count, 0, -1):
            server.dele(i)
        server.quit()  # 确保断开连接


def get_login_code(email, password, pop_server):
    for i in range(3):
        time.sleep(3)
        result = fetch_latest_email_token(email, password, pop_server)
        if result:
            return result
        else:
            logging.error("获取登录令牌失败{}, {}, {}".format(i, email, password))

            continue


def email_code(email, password, pop_server):
    pop_server = pop_server.split(":")
    def guess_charset(msg):
        charset = msg.get_charset()
        if charset is None:
            content_type = msg.get('Content-Type', '').lower()
            pos = content_type.find('charset=')
            if pos >= 0:
                charset = content_type[pos + 8:].strip()
                if ";" in charset:
                    charset = charset.split(";")[0]
        return charset

    def decode_str(s):
        value, charset = decode_header(s)[0]
        if charset:
            value = value.decode(charset)
        return value

    def parse_email(msg, indent=0):
        mail_object = dict()
        if indent == 0:
            for header in ['From', 'To', 'Subject', 'Received']:
                value = msg.get(header, '')
                if value:
                    if header == 'Subject':
                        value = decode_str(value)
                    if header == 'Received':
                        if not mail_object.get('date'):
                            date_value = re.compile('\d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2}').findall(value)
                            if date_value:
                                mail_object['date'] = datetime.strptime(date_value[0], "%d %b %Y %H:%M:%S")

                    else:
                        hdr, addr = parseaddr(value)
                        name = decode_str(hdr)
                        value = u'%s <%s>' % (name, addr)
                    mail_object.update({header: value})
        if (msg.is_multipart()):
            parts = msg.get_payload()
            for n, part in enumerate(parts):
                parse_message = parse_email(part, indent + 1)
                if indent == 0:
                    has_message = mail_object.get('message', '')
                    has_message += u'{}\r\n'.format(parse_message)
                    mail_object.update({'message': has_message})
                else:
                    return parse_message
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
                content = msg.get_payload(decode=True)
                charset = guess_charset(msg)
                if charset:
                    content = content.decode(charset, "replace")
                    if indent == 0:
                        has_message = mail_object.get('message', '')
                        has_message += u'{}\r\n'.format(content)
                        mail_object.update({'message': has_message})
                    else:
                        return content
        return mail_object

    try:
        if pop_server[1] == '110':
            # 测试微软需要SSL
            server = poplib.POP3(pop_server[0], 110)
        else:
            server = poplib.POP3_SSL(pop_server[0], 995)
    except:
        logging.error("邮箱服务器链接失败")
        return None
    try:
        server.user(email)
        server.pass_(password)
    except:
        logging.info("email:{}邮箱账户或者密码错误".format(email))
        return None
    mail_messages, mail_size = server.stat()
    resp, mails, octets = server.list()
    if mail_messages == 0:
        return None
    # 解析邮件
    index = len(mails)
    if index >= 2:
        messages = [server.retr(i) for i in range(index, index - 2, -1)]
    else:
        messages = [server.retr(index)]
    for message in messages:
        try:
            resp, lines, octets = message
            # 解析邮件:
            msg = Parser().parsestr('\r\n'.join([line.decode() for line in lines]))
            # 邮件内容:
            mail_object = parse_email(msg)
            # print(mail_object)
            if "noreply@steampowered.com" in mail_object.get("From", ""):
                # 优先处理找回账户的链接
                login_code = re.findall('href="(https://help.steampowered.com/[^"]+/wizard/HelpWithLogin)"',
                                        mail_object.get('message', ''))
                if login_code:
                    logging.info("邮箱:{}已经注册了steam了".format(email))
                    return login_code[0]
                code = re.findall(r'href="(https://store.steampowered.com/account/steamguarddisableverification\?'
                                  r'stoken=[^"]+)"', mail_object.get('message', ''))
                if code:
                    return code[0]
            else:
                continue
        except Exception as e:
            logging.info("解析邮件失败,message:[{}]".format(e))


def get_close_guard_link(email, password, pop_server):
    for i in range(3):
        time.sleep(3)
        result = email_code(email, password, pop_server)
        if result:
            return result
        else:
            logging.error("获取关闭令牌链接失败{}, {}, {}".format(i, email, password))

            continue
