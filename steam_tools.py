from bs4 import BeautifulSoup

'''
正则最近掉落记录
'''
def regex_recently_dropped(text, num=2):
    inventory_list = []
    soup = BeautifulSoup(text, 'html.parser')

    # 找到所有的交易历史记录
    trade_history_rows = soup.find_all("div", class_="tradehistoryrow")

    # 初始化一个列表来收集符合条件的记录
    matched_records = []

    # 对每一条记录进行处理
    for row in trade_history_rows:
        event_description = row.find("div", class_="tradehistory_event_description").get_text(strip=True)
        if "已提升到新等级并获得物品掉落" in event_description:
            # 如果记录符合条件，加入到列表中
            matched_records.append(row)

    # matched_records 包含了所有符合条件的记录
    # 从这个列表中提取前两条记录
    for row in matched_records[:num]:
        date = row.find("div", class_="tradehistory_date").get_text(strip=True)
        item_name = row.find("span", class_="history_item_name").get_text(strip=True)
        inventory_list.append({
            'date': date,
            'item_name': item_name
        })
    return inventory_list
