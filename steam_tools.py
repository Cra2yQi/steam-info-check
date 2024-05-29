from bs4 import BeautifulSoup
from datetime import datetime
import json

'''
正则最近掉落记录
'''


def regex_recently_dropped(html_text, date_str):
    if date_str:
        # 转换日期字符串为日期对象
        target_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")

    soup = BeautifulSoup(html_text, 'html.parser')
    trade_history_rows = soup.find_all("div", class_="tradehistoryrow")
    matched_records = []

    # 收集符合描述条件的记录
    for row in trade_history_rows:
        event_description = row.find("div", class_="tradehistory_event_description").get_text(strip=True)
        if "已提升到新等级并获得物品掉落" in event_description:
            row_date_str = row.find("div", class_="tradehistory_date").get_text(strip=True)
            row_date = parse_chinese_datetime(row_date_str)
            item_name = row.find("span", class_="history_item_name").get_text(strip=True)
            if date_str is not None:
                if row_date >= target_date:
                    matched_records.append({
                        'date': row_date,
                        'item_name': item_name
                    })
            else:
                matched_records.append({
                    'date': row_date,
                    'item_name': item_name
                })
    if not matched_records:
        return []

    # 确定最新日期
    latest_date = max(
        row['date']
        for row
        in matched_records)

    # 从最新日期的记录中提取信息
    inventory_list = []
    for row in matched_records:
        if row['date'] == latest_date:
            inventory_list.append({
                'date': row['date'].strftime("%Y-%m-%d %H:%M:%S"),
                'item_name': row['item_name']
            })

    return inventory_list


def parse_chinese_datetime(date_str):
    # 替换中文日期部分为标准格式
    date_str = date_str.replace(' ', '').strip()
    date_str = date_str.replace("年", "-").replace("月", "-").replace("日", " ").strip()

    # 分离日期和时间部分
    date_part, time_part = date_str.split(' ')

    # 提取“上午/下午”部分并调整时间
    period = time_part[:2]  # 上午或下午
    time_part = time_part[2:].strip()  # 时间部分，如'5:21'

    # 转换时间为24小时制
    hour, minute = map(int, time_part.split(':'))
    if period == '下午' and hour != 12:
        hour += 12
    elif period == '上午' and hour == 12:
        hour = 0  # 午夜12点应为00:00

    # 构造24小时制的时间字符串
    time_part = f"{hour:02d}:{minute:02d}:00"

    # 合并日期和时间部分，并解析为datetime对象
    datetime_str = f"{date_part} {time_part}"
    return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")


def regex_profile(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    # 查找'CS:GO Profile Rank'
    rank_div = soup.find('div', string=lambda text: 'CS:GO Profile Rank' in text if text else False)
    rank = rank_div.text.split(':')[-1].strip() if rank_div else None
    rank_div = soup.find('div',
                         string=lambda text: 'Experience points earned towards next rank' in text if text else False)
    experience = rank_div.text.split(':')[-1].strip() if rank_div else None
    if experience:
        experience = int(experience)
    # 查找所有行<tr>
    table_rows = soup.find_all('tr')
    login_time = None
    # 遍历行查找特定的记录
    for row in table_rows:
        cells = row.find_all('td')  # 查找行内所有的<td>
        if cells:  # 确保<td>存在
            activity = cells[0].text.strip()
            if activity == 'Logged out of CS:GO':
                login_time = cells[1].text.strip()  # 获取时间文本
                break
    return {"rank": rank, "experience": experience, "login_time": login_time}


def regex_vac(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    vac_span = soup.find_all("span", class_="help_highlight_text")
    for item in vac_span:
        if 'Counter-Strike 2' in item:
            return True
    return False


def regex_contest(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    table = soup.find_all('table', class_='generic_kv_table')
    re_text = ''
    for item in table:
        rows = item.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            if cells and '竞技模式' in cells[0].text:
                map = cells[1].text.strip()
                win = cells[2].text.strip()
                re_text += f'{map}----{win} '
    return re_text


def regex_close_guard(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    list = soup.find('div', class_='phone_box').get_text(strip=True)
    if list == '须经确认后才能关闭 Steam 令牌。我们已向您发送了含有禁用 Steam 令牌确认链接的邮件。':
        return True
    else:
        return False


def regex_close_guard2(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    list = soup.find('h2', class_='pageheader').get_text(strip=True)
    if list == 'Steam 令牌已禁用':
        return True
    else:
        return False

def regex_user_info(html_text):
    info = {
        'balance': None,
        'country': None,
        'steam64id': None,
        'steam17id': None,
    }
    soup = BeautifulSoup(html_text, 'html.parser')
    wallet_balance_tag = soup.find("a", id="header_wallet_balance")
    if wallet_balance_tag:
        # 提取 <a> 标签的文本内容
        wallet_balance = wallet_balance_tag.get_text().strip()
        info['balance'] = wallet_balance
    div_tag = soup.find('div', id='webui_config')

    # 获取data-userinfo属性值
    userinfo_json = div_tag['data-userinfo']
    userinfo_dict = json.loads(userinfo_json)

    # 提取steamid和country_code
    steam64id = userinfo_dict.get('steamid', None)
    country_code = userinfo_dict.get('country_code', None)
    steam17id = userinfo_dict.get('accountid', None)
    if steam64id:
        info['steam64id'] = steam64id
    if country_code:
        info['country'] = country_code
    if steam17id:
        info['steam17id'] = steam17id
    return info
