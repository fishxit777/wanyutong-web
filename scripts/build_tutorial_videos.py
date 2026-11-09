from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H, FPS = 1920, 1080, 30
BG, PANEL, TEXT, MUTED, GREEN, CYAN = "#080b10", "#111822", "#f4f7fb", "#adbac8", "#06c755", "#00d4ff"
VOICE = "Microsoft Yating"
RELEASE_DATE = "20261110"
DISPLAY_DATE = "2026-11-10"

VIDEOS = {'line-bot-tutorial': {'eyebrow': 'LINE 常用功能｜2026-11-10',
                       'title': '私訊與群組，這樣開始',
                       'slides': [('私訊：點底部選單', '手機私訊可直接點六個常用入口', ['語言設定｜持續多語｜用量與到期', '方案｜新手教學｜客服']),
                                  ('群組：傳送 @選單', 'LINE 群組不支援固定底部圖文選單', ['傳純文字 @選單，開聊天內功能卡', '不必標記萬語通機器人']),
                                  ('語言設定，直接選', '傳送 @語言設定 或 @多語', ['快捷組合可直接套用', '自選雙語或持續多語，舊指令也保留']),
                                  ('主語言先顯示', '總支援 36 種；持續多語最多同時 8 種', ['第一個指定目標是可複製文字', '其他語言以按鈕逐一查看']),
                                  ('按鈕只讀快取', '24 小時內不重翻、不再扣額度', ['點選後全群可見，並非私人翻譯', '同一語言每則原始訊息最多公開一次']),
                                  ('免費額度與提醒',
                                   '原文與全部目標都在中英日韓：不計每日額度',
                                   ['任一超出四語：每天 50 則原始訊息', '剩 5、3、1、0 則時提醒，可主動查用量']),
                                  ('TAG 與翻譯一起保留',
                                   '真正選取群組成員或 All，再輸入文字',
                                   ['手打 @姓名 只保留文字，不會真的標人', '標記機器人維持不回覆']),
                                  ('翻譯仍需對照原文', '檢查疑點時，附提醒並提供原譯文', ['提醒不等於已證實翻錯', '金額、日期、工安等資訊請人工確認']),
                                  ('切換模式與取得協助', '設定新的有效雙語，會自動關閉多語', ['@多語 關閉：回到原雙語', '@新手教學｜@客服'])],
                       'narration_parts': ['在手機與萬語通的私訊中，點底部選單，就能開啟語言設定、持續多語、用量與到期、方案、新手教學和客服。',
                                           'LINE 平台目前不支援群組固定底部圖文選單。在群組傳送純文字，小老鼠選單，就會開啟聊天內的六個功能入口，不必標記機器人。',
                                           '傳送小老鼠語言設定，或小老鼠多語，即可用按鈕選擇。可以直接套用快捷組合，也保留原本帶語言名稱的指令。',
                                           '總支援三十六種語言，持續多語最多同時設定八種。第一個指定目標先顯示為可複製文字，其他語言以按鈕逐一查看。',
                                           '語言按鈕只讀取二十四小時快取，不會重新翻譯，也不會再次扣額度。群組點選後全群可見，同一語言每則原始訊息最多公開一次。',
                                           '原文與所有目標都在中文、英文、日文、韓文內，不計每日額度。原文或任一指定目標超出四語，每則原始訊息計一則，每日五十則。只在剩五、三、一、零則時提醒；個人各自計算，群組共同使用。',
                                           '從 LINE 提及清單選取成員或 '
                                           'All，可以一起保留標記與翻譯。手打小老鼠加姓名，只會保留文字，不會猜測身分。標記萬語通機器人仍不回覆。',
                                           '系統發現關鍵資訊疑點時，會附上提醒並提供原譯文。提醒不等於已證實翻錯，也不保證所有錯誤都能發現。金額、日期與高風險內容，請對照原文確認。',
                                           '要離開多語，傳送小老鼠多語，空格，關閉；或設定新的有效雙語，系統會自動關閉多語。需要操作說明可用小老鼠新手教學，問題持續請用小老鼠客服。'],
                       'narration': '在手機與萬語通的私訊中，點底部選單，就能開啟語言設定、持續多語、用量與到期、方案、新手教學和客服。LINE '
                                    '平台目前不支援群組固定底部圖文選單。在群組傳送純文字，小老鼠選單，就會開啟聊天內的六個功能入口，不必標記機器人。傳送小老鼠語言設定，或小老鼠多語，即可用按鈕選擇。可以直接套用快捷組合，也保留原本帶語言名稱的指令。總支援三十六種語言，持續多語最多同時設定八種。第一個指定目標先顯示為可複製文字，其他語言以按鈕逐一查看。語言按鈕只讀取二十四小時快取，不會重新翻譯，也不會再次扣額度。群組點選後全群可見，同一語言每則原始訊息最多公開一次。原文與所有目標都在中文、英文、日文、韓文內，不計每日額度。原文或任一指定目標超出四語，每則原始訊息計一則，每日五十則。只在剩五、三、一、零則時提醒；個人各自計算，群組共同使用。從 '
                                    'LINE 提及清單選取成員或 '
                                    'All，可以一起保留標記與翻譯。手打小老鼠加姓名，只會保留文字，不會猜測身分。標記萬語通機器人仍不回覆。系統發現關鍵資訊疑點時，會附上提醒並提供原譯文。提醒不等於已證實翻錯，也不保證所有錯誤都能發現。金額、日期與高風險內容，請對照原文確認。要離開多語，傳送小老鼠多語，空格，關閉；或設定新的有效雙語，系統會自動關閉多語。需要操作說明可用小老鼠新手教學，問題持續請用小老鼠客服。'},
 'secretary-tutorial': {'eyebrow': 'AI 祕書｜付費群組功能',
                        'title': '摘要協助整理，重要事項人工確認',
                        'slides': [('只整理這個群組', 'AI 祕書是付費群組功能', ['先確認方案與紀錄功能已啟用', '不讀取其他群組或私人對話']),
                                   ('先看說明與狀態', '@祕書 與 @秘書，兩種寫法皆可', ['@祕書 說明：查看可用功能', '@祕書 狀態：確認目前設定']),
                                   ('安靜地記錄', '可只記錄，不自動插話', ['自動回覆預設關閉', '摘要需有可整理的群組紀錄']),
                                   ('摘要與交班', '@祕書 摘要｜@祕書 報表', ['整理近期已記錄內容', '依回覆標示的實際整理筆數核對']),
                                   ('人工確認，留下回覆', '整理結果不等於逐人已讀或理解', ['重要工作請成員主動文字回覆', '不宣稱自動取得誰已讀、誰理解']),
                                   ('核對來源與取得協助', '翻譯、摘要都有可能出錯', ['金額、日期、工安等請回看原文', '問題持續：@客服'])],
                        'narration_parts': ['萬語通 AI 秘書是付費群組功能，只整理該群組已留下的紀錄。請先確認群組方案與紀錄功能已啟用，不會讀取其他群組或私人對話。',
                                            '小老鼠祕書與小老鼠秘書兩種寫法都可以。先傳送小老鼠祕書，空格，說明，再用小老鼠祕書，空格，狀態，核對目前設定。',
                                            'AI 秘書可以只記錄，不自動插話，自動回覆預設關閉。沒有可用紀錄，或紀錄與摘要模式未啟用，就不能把空白結果當成當天沒有事情。',
                                            '傳送小老鼠祕書，空格，摘要，可整理近期已記錄內容；需要交班資訊可用小老鼠祕書，空格，報表。請依回覆標示的實際整理筆數核對，不把摘要範圍當成搜尋或匯出上限。',
                                            '摘要只是協助整理。重要工作請成員主動以文字回覆，再由主管核對。系統不會因為送出翻譯，就知道誰已讀、誰已理解，或工作是否完成。',
                                            '翻譯與摘要都有可能出錯。金額、日期、工安、醫療與合約等重要事項，務必回看原文並由合適的人員確認。問題持續，請使用小老鼠客服反映。'],
                        'narration': '萬語通 AI '
                                     '秘書是付費群組功能，只整理該群組已留下的紀錄。請先確認群組方案與紀錄功能已啟用，不會讀取其他群組或私人對話。小老鼠祕書與小老鼠秘書兩種寫法都可以。先傳送小老鼠祕書，空格，說明，再用小老鼠祕書，空格，狀態，核對目前設定。AI '
                                     '秘書可以只記錄，不自動插話，自動回覆預設關閉。沒有可用紀錄，或紀錄與摘要模式未啟用，就不能把空白結果當成當天沒有事情。傳送小老鼠祕書，空格，摘要，可整理近期已記錄內容；需要交班資訊可用小老鼠祕書，空格，報表。請依回覆標示的實際整理筆數核對，不把摘要範圍當成搜尋或匯出上限。摘要只是協助整理。重要工作請成員主動以文字回覆，再由主管核對。系統不會因為送出翻譯，就知道誰已讀、誰已理解，或工作是否完成。翻譯與摘要都有可能出錯。金額、日期、工安、醫療與合約等重要事項，務必回看原文並由合適的人員確認。問題持續，請使用小老鼠客服反映。'},
 'activation-flow': {'eyebrow': '方案與開通｜指定群組',
                     'title': '先確認群組，再完成付款',
                     'slides': [('免費版先開始', '加入即可使用免費文字翻譯', ['原文與全部目標皆中英日韓：不計每日額度', '任一超出四語：每天 50 則原始訊息']),
                                ('低額度才提醒', '剩 5、3、1、0 則時提醒', ['個人各自計算，群組共同使用', '可從選單主動查看用量']),
                                ('現行付費方案',
                                 '每個方案只適用於指定的一個群組',
                                 ['月費 NT$99／30 天｜半年 NT$499／180 天', '一年 NT$799／420 天｜尊爵 NT$2500／永久']),
                                ('第一步：指定群組', '加入官方帳號，再把 Bot 加進要使用的群組', ['在該群組傳送 @方案', '只使用 Bot 回覆的官方付款連結']),
                                ('第二步：付款後核對',
                                 '系統驗證付款回呼後，開通或延長指定群組',
                                 ['金額與期間以送出前訂購畫面為準', '付款後超過 5 分鐘未開通：@客服']),
                                ('第三步：依方案使用', '語音、圖片 OCR、摘要與紀錄工具', ['到群組用 @選單 開常用入口', '重要內容仍請人工確認'])],
                     'narration_parts': ['萬語通免費版零元。原文與所有指定目標都在中文、英文、日文、韓文內，不計每日額度。原文或任一指定目標超出四語，每則原始訊息計一則，每日五十則；多個目標仍只計一則。',
                                         '額度不必每次顯示，只在剩五、三、一、零則時提醒。個人按使用者計算，群組由全群組共用；也可以從選單主動查看用量。',
                                         '目前付費方案都是指定群組使用。月費版九十九元，三十天；半年版四百九十九元，一百八十天；一年版七百九十九元，四百二十天；尊爵版兩千五百元，每群組永久買斷。',
                                         '加入萬語通官方帳號，再把 Bot 加進要開通的群組。在那個群組傳送小老鼠方案，只使用 Bot '
                                         '回覆的官方付款連結。不要使用陌生私訊或轉傳的付款網址。',
                                         '正式付款回呼通過驗證後，系統才開通或延長指定群組。金額、期間與是否續扣，請看送出前的訂購畫面。付款超過五分鐘還沒開通，請用小老鼠客服查核，不要再次付款。',
                                         '開通後依方案使用語音、圖片文字辨識、AI '
                                         '秘書摘要與紀錄工具。群組傳送小老鼠選單，可開啟常用入口。翻譯與摘要可能有誤，重要內容仍請人工確認。'],
                     'narration': '萬語通免費版零元。原文與所有指定目標都在中文、英文、日文、韓文內，不計每日額度。原文或任一指定目標超出四語，每則原始訊息計一則，每日五十則；多個目標仍只計一則。額度不必每次顯示，只在剩五、三、一、零則時提醒。個人按使用者計算，群組由全群組共用；也可以從選單主動查看用量。目前付費方案都是指定群組使用。月費版九十九元，三十天；半年版四百九十九元，一百八十天；一年版七百九十九元，四百二十天；尊爵版兩千五百元，每群組永久買斷。加入萬語通官方帳號，再把 '
                                  'Bot 加進要開通的群組。在那個群組傳送小老鼠方案，只使用 Bot '
                                  '回覆的官方付款連結。不要使用陌生私訊或轉傳的付款網址。正式付款回呼通過驗證後，系統才開通或延長指定群組。金額、期間與是否續扣，請看送出前的訂購畫面。付款超過五分鐘還沒開通，請用小老鼠客服查核，不要再次付款。開通後依方案使用語音、圖片文字辨識、AI '
                                  '秘書摘要與紀錄工具。群組傳送小老鼠選單，可開啟常用入口。翻譯與摘要可能有誤，重要內容仍請人工確認。'}}


def run(args: list[str], capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture)


def fnt(size: int, bold=False):
    p = Path(r"C:\Windows\Fonts\msjhbd.ttc" if bold else r"C:\Windows\Fonts\msjh.ttc")
    return ImageFont.truetype(str(p), size)


def script_fnt(text: str, size: int, bold=False):
    """Use a Hangul-capable face where Microsoft JhengHei has no glyphs."""
    if re.search(r"[\uac00-\ud7af]", str(text or "")):
        p = Path(r"C:\Windows\Fonts\malgunbd.ttf" if bold else r"C:\Windows\Fonts\malgun.ttf")
        return ImageFont.truetype(str(p), size)
    return fnt(size, bold)


def wrap(draw, text, face, width):
    out, cur = [], ""
    for c in text:
        if draw.textlength(cur + c, font=face) <= width:
            cur += c
        else:
            out.append(cur); cur = c
    if cur: out.append(cur)
    return out


def draw_visual(d: ImageDraw.ImageDraw, title: str, sub: str, x=1190, y=315):
    """Draw a deliberately fictional UI vignette; never uses production/customer data."""
    d.rounded_rectangle((x, y, 1755, 825), radius=30, fill="#0a1119", outline="#304457", width=3)
    d.text((x + 36, y + 26), "示意畫面", font=fnt(24, True), fill="#7890a3")
    if "私訊" in title or "群組：" in title:
        d.text((x+42,y+93), "手機私訊" if "私訊" in title else "群組聊天內功能卡", font=fnt(32,True), fill=TEXT)
        if "群組：" in title:
            d.rounded_rectangle((x+38,y+155,x+527,y+220),radius=14,fill="#123d25")
            d.text((x+68,y+171),"@選單",font=fnt(30,True),fill=TEXT)
        for n, label in enumerate(("語言設定","持續多語","用量與到期","方案","新手教學","客服")):
            bx=x+38+(n%2)*250; by=y+250+(n//2)*70
            d.rounded_rectangle((bx,by,bx+235,by+58),radius=12,fill="#102431",outline=CYAN,width=2)
            d.text((bx+22,by+13),label,font=fnt(24,True),fill=TEXT)
        d.text((x+42,y+477),"示意：群組卡片不會固定在底部",font=fnt(22),fill=MUTED)
    elif "直接選" in title:
        d.text((x+42,y+95),"@語言設定",font=fnt(32,True),fill=CYAN)
        for n, label in enumerate(("繁體中文 ↔ 英文","繁體中文 ↔ 日文","自選雙語")):
            by=y+176+n*90
            d.rounded_rectangle((x+38,by,x+527,by+68),radius=16,fill="#14202c",outline=GREEN,width=2)
            d.text((x+65,by+18),label,font=fnt(28,True),fill=TEXT)
    elif "人工確認" in title:
        d.text((x+42,y+105),"主管：請回覆是否收到",font=fnt(28,True),fill=TEXT)
        d.rounded_rectangle((x+42,y+200,x+525,y+285),radius=18,fill="#123d25")
        d.text((x+67,y+225),"成員：收到，稍後核對",font=fnt(28,True),fill=TEXT)
        d.text((x+42,y+368),"一般文字回覆示意",font=fnt(28,True),fill=CYAN)
        d.text((x+42,y+422),"不代表已讀、理解或完成工作",font=fnt(24),fill=MUTED)
    elif "額度" in title or "免費版" in title:
        d.rounded_rectangle((x+38,y+98,x+527,y+206),radius=18,fill="#112b1d",outline=GREEN,width=2)
        d.text((x+65,y+123),"今日剩餘",font=fnt(27,True),fill="#d8ffe5")
        d.text((x+330,y+118),"5/50",font=fnt(36,True),fill=CYAN)
        d.rounded_rectangle((x+38,y+246,x+527,y+428),radius=18,fill="#14202c",outline="#304457",width=2)
        d.text((x+62,y+270),"原文＋所有指定目標",font=fnt(26,True),fill=TEXT)
        d.text((x+62,y+318),"任一超出中英日韓",font=fnt(25),fill=MUTED)
        d.text((x+62,y+369),"每則原始訊息計 1 則",font=fnt(27,True),fill="#bff4cf")
    elif "主語言" in title or "按鈕" in title:
        d.rounded_rectangle((x+38,y+92,x+527,y+203),radius=18,fill="#13241c",outline=GREEN,width=2)
        d.text((x+62,y+112),"主語言｜繁體中文",font=fnt(24,True),fill="#bff4cf")
        d.text((x+62,y+157),"可直接選取、複製文字",font=fnt(25),fill=TEXT)
        cy=y+242
        for label in ("English", "日本語", "한국어"):
            d.rounded_rectangle((x+38,cy,x+527,cy+60),radius=16,fill="#102431",outline=CYAN,width=2)
            d.text((x+64,cy+14),label,font=script_fnt(label,24,True),fill="#d8f7ff")
            d.text((x+430,cy+14),"查看",font=fnt(22,True),fill=CYAN)
            cy += 72
        d.text((x+112,y+474),"24 小時快取｜不重翻、不再扣",font=fnt(22,True),fill=MUTED)
    elif "方案" in title or "付款" in title or "免費" in title or "開通" in title or "指定群組" in title:
        if "現行付費方案" in title:
            cards=[("免費版","NT$0｜加入即用"),("月費版","NT$99｜30 天"),("半年版","NT$499｜180 天"),("一年版","NT$799｜420 天"),("尊爵版","NT$2500｜永久")]
            cy=y+78
            for name,price in cards:
                d.rounded_rectangle((x+34,cy,x+531,cy+68),radius=14,fill="#14202c",outline=GREEN if name!="免費版" else CYAN,width=2)
                d.text((x+53,cy+15),name,font=fnt(22,True),fill=TEXT); d.text((x+215,cy+15),price,font=fnt(22,True),fill="#bff4cf"); cy+=78
        elif "指定群組" in title:
            steps = [("指定群組", GREEN), ("@方案", CYAN), ("官方付款頁", GREEN)]
            cy = y + 86
            for index, (label, color) in enumerate(steps):
                d.rounded_rectangle((x+55,cy,x+510,cy+82),radius=18,fill="#14202c",outline=color,width=2)
                d.text((x+90,cy+22),label,font=fnt(28,True),fill=TEXT)
                if index < len(steps) - 1:
                    d.text((x+255,cy+86),"↓",font=fnt(30,True),fill=CYAN)
                cy += 132
        else:
            d.rounded_rectangle((x+38,y+105,x+527,y+205),radius=18,fill="#14202c",outline=GREEN,width=2)
            d.text((x+64,y+130),"指定群組",font=fnt(29,True),fill=TEXT)
            d.text((x+212,y+248),"↓",font=fnt(36,True),fill=CYAN)
            d.rounded_rectangle((x+38,y+310,x+527,y+410),radius=18,fill="#13241c",outline=GREEN,width=2)
            d.text((x+72,y+336),"Bot 官方付款連結",font=fnt(28,True),fill="#d8ffe5")
    elif "祕書" in title or "重點" in title or "交班" in title or "記錄" in title or "AI" in title:
        cy=y+98
        for label,value,color in [("翻譯","● 開啟",GREEN),("紀錄","● 開啟",GREEN),("自動回覆","○ 關閉",MUTED)]:
            d.text((x+52,cy),label,font=fnt(27,True),fill=TEXT); d.text((x+320,cy),value,font=fnt(27,True),fill=color); cy+=70
        d.rounded_rectangle((x+42,y+345,x+525,y+455),radius=20,fill="#13241c",outline=GREEN,width=2)
        d.text((x+70,y+372),"摘要  ·  報表  ·  交班",font=fnt(26,True),fill="#c9f8d8")
    elif "兩種" in title or "離開" in title:
        d.rounded_rectangle((x+50,y+100,x+510,y+182),radius=20,fill="#112b1d",outline=GREEN,width=2)
        d.text((x+76,y+123),"@多語 關閉",font=fnt(28,True),fill="#d8ffe5")
        d.text((x+245,y+207),"或",font=fnt(28,True),fill=CYAN)
        d.rounded_rectangle((x+50,y+250,x+510,y+342),radius=20,fill="#102431",outline=CYAN,width=2)
        d.text((x+69,y+279),"@語言設定 繁體中文 英文",font=fnt(22,True),fill="#d8f7ff")
        d.text((x+112,y+400),"→  回到雙語模式",font=fnt(26,True),fill=MUTED)
    else:
        # Fictional LINE-like conversation with generic roles only.
        d.ellipse((x+42,y+104,x+102,y+164),fill="#274056"); d.text((x+59,y+119),"A",font=fnt(24,True),fill=TEXT)
        d.rounded_rectangle((x+120,y+92,x+508,y+180),radius=22,fill="#1a2b3a")
        d.text((x+147,y+116),"主管：請確認今日工作",font=fnt(24,True),fill=TEXT)
        d.ellipse((x+455,y+218,x+515,y+278),fill="#245536"); d.text((x+473,y+233),"B",font=fnt(24,True),fill=TEXT)
        d.rounded_rectangle((x+56,y+210,x+435,y+298),radius=22,fill="#123d25")
        d.text((x+83,y+234),"員工 B：已收到，謝謝",font=fnt(24,True),fill="#dcffe7")
        d.rounded_rectangle((x+55,y+354,x+515,y+437),radius=18,fill="#101e29",outline=CYAN,width=2)
        cmd = "@語言設定 繁體中文 印尼文" if "雙語" in title else ("@多語 繁體中文 英文 …" if "多語" in title else "@說明")
        d.text((x+82,y+378),cmd,font=fnt(24,True),fill=CYAN)
        d.text((x+95,y+461),"同一群組 · 同一份結果",font=fnt(24,True),fill=MUTED)


def slide_image(path: Path, spec: dict, index: int, slide: tuple[str, str, list[str]], logo_path: Path):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    for x in range(-H, W, 96):
        d.line((x, 0, x + H, H), fill="#0e1922", width=2)
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0)); gd = ImageDraw.Draw(glow)
    gd.ellipse((1300, -350, 2200, 550), fill=(0, 212, 255, 34)); gd.ellipse((-300, 650, 600, 1450), fill=(6, 199, 85, 28))
    im = Image.alpha_composite(im.convert("RGBA"), glow.filter(ImageFilter.GaussianBlur(75))).convert("RGB"); d = ImageDraw.Draw(im)
    d.rectangle((0, 0, W, 12), fill=GREEN); d.rectangle((0, H - 8, W, H), fill=CYAN)
    logo = Image.open(logo_path).convert("RGB"); logo.thumbnail((96, 96), Image.Resampling.LANCZOS)
    mask = Image.new("L", logo.size); ImageDraw.Draw(mask).ellipse((0, 0, *logo.size), fill=255)
    im.paste(logo, (86, 66), mask); d = ImageDraw.Draw(im)
    d.text((205, 77), "萬語通 WanyuTong", font=fnt(40, True), fill=TEXT)
    d.text((205, 128), spec["eyebrow"], font=fnt(24), fill=CYAN)
    d.rounded_rectangle((1660, 72, 1835, 130), radius=29, outline=GREEN, width=3)
    d.text((1708, 87), f"{index+1:02d} / {len(spec['slides']):02d}", font=fnt(23, True), fill="#9ef3bc")
    title, sub, bullets = slide
    d.rounded_rectangle((80, 230, 1840, 914), radius=38, fill=PANEL, outline="#253343", width=2)
    d.rectangle((80, 230, 94, 914), fill=GREEN if index % 2 == 0 else CYAN)
    y = 292
    for line in wrap(d, title, fnt(62, True), 950):
        d.text((160, y), line, font=fnt(62, True), fill=TEXT); y += 88
    y += 12
    for line in wrap(d, sub, fnt(39), 940):
        d.text((164, y), line, font=fnt(39), fill=MUTED); y += 55
    y += 28
    for b in bullets:
        d.rounded_rectangle((160, y + 4, 190, y + 34), radius=8, fill=GREEN)
        for line in wrap(d, b, fnt(40, True), 850):
            d.text((220, y), line, font=fnt(40, True), fill="#e9f7ef"); y += 58
        y += 25
    draw_visual(d, title, sub)
    d.text((160, 962), f"{DISPLAY_DATE} 功能圖解｜示意畫面，非實機錄影｜重要資訊請人工確認", font=fnt(23), fill="#718091")
    im.save(path, quality=96)


def srt_to_vtt(srt: Path, vtt: Path):
    text = srt.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    text = re.sub(r"(?<=\d),(?=\d{3})", ".", text).strip()
    vtt.write_text("WEBVTT\n\n" + text + "\n", encoding="utf-8")


def escape_filter_path(p: Path):
    return str(p).replace("\\", "/").replace(":", r"\:").replace("'", r"\'")


def srt_seconds(value: str) -> float:
    h, m, sec = value.replace(",", ".").split(":")
    return int(h) * 3600 + int(m) * 60 + float(sec)


def srt_time(value: float) -> str:
    ms = round(value * 1000)
    return f"{ms//3600000:02}:{ms//60000%60:02}:{ms//1000%60:02},{ms%1000:03}"


def shifted_cues(path: Path, offset: float) -> list[tuple[float, float, str]]:
    content = path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    result = []
    for block in re.split(r"\n\s*\n", content.strip()):
        rows = block.splitlines()
        timing = next((i for i, row in enumerate(rows) if " --> " in row), None)
        if timing is None:
            continue
        begin, end = rows[timing].split(" --> ")
        result.append((srt_seconds(begin) + offset, srt_seconds(end) + offset, "\n".join(rows[timing+1:])))
    return result


def duration_of(path: Path) -> float:
    probe = run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)], True)
    return float(json.loads(probe.stdout)["format"]["duration"])


def synthesize_offline(narration: str, folder: Path, name: str, audio: Path, srt: Path):
    """Use an installed Windows voice; synthesis never contacts a hosted service."""
    # Short phrase clips provide exact subtitle boundaries without estimated timings.
    phrases = []
    for clause in re.findall(r"[^，。；！？]+[，。；！？]?", narration):
        while len(clause) > 24:
            boundaries = [clause.rfind(mark, 8, 24) + 1 for mark in ("、", " ")]
            cut = max(boundaries) or 24
            phrases.append(clause[:cut])
            clause = clause[cut:]
        if clause:
            phrases.append(clause)
    records = [{"text": phrase, "path": str(folder / f"{name}-phrase-{i:02d}.wav")} for i,phrase in enumerate(phrases)]
    request = folder / f"{name}-phrases.json"
    request.write_text(json.dumps(records,ensure_ascii=False),encoding="utf-8-sig")
    helper = folder / "synthesize-offline.ps1"
    helper.write_text(r"""param([string]$RequestPath,[string]$VoiceName)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
$speaker = [System.Speech.Synthesis.SpeechSynthesizer]::new()
try {
  $speaker.SelectVoice($VoiceName)
  $speaker.Rate = 0
  $speaker.Volume = 100
  $items = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($item in $items) {
    $speaker.SetOutputToWaveFile([string]$item.path)
    $speaker.Speak([string]$item.text)
    $speaker.SetOutputToNull()
  }
} finally { $speaker.Dispose() }
""",encoding="utf-8-sig")
    run(["pwsh", "-NoProfile", "-File", str(helper), "-RequestPath", str(request), "-VoiceName", VOICE])
    files = folder / f"{name}-audio.txt"
    files.write_text("\n".join("file '"+Path(row["path"]).as_posix()+"'" for row in records),encoding="utf-8")
    elapsed, cue_rows = 0.0, []
    for i,row in enumerate(records):
        end = elapsed + duration_of(Path(row["path"]))
        cue_rows.append(f"{i+1}\n{srt_time(elapsed)} --> {srt_time(end)}\n{row['text']}")
        elapsed = end
    srt.write_text("\n\n".join(cue_rows)+"\n",encoding="utf-8")
    run(["ffmpeg","-y","-hide_banner","-loglevel","error","-f","concat","-safe","0","-i",str(files),"-c:a","libmp3lame","-b:a","128k",str(audio)])


def build_one(key: str, spec: dict, repo: Path, work: Path, output: Path, release_date: str):
    folder = work / key
    folder.mkdir(parents=True, exist_ok=True)
    logo = repo / "assets" / "wanyutong-logo.jpg"
    output.mkdir(parents=True, exist_ok=True)
    slides, segments, cues, timeline = [], [], [], []
    elapsed = 0.0
    for i, (slide, narration) in enumerate(zip(spec["slides"], spec["narration_parts"], strict=True)):
        image = folder / f"slide-{i+1:02d}.png"
        slide_image(image, spec, i, slide, logo)
        slides.append(image)
        txt, mp3, srt = (folder / f"voice-{i+1:02d}{ext}" for ext in (".txt", ".mp3", ".srt"))
        digest_path = folder / f"voice-{i+1:02d}.sha256"
        phrase_version = "v2" if any(len(c) > 24 for c in re.findall(r"[^，。；！？]+[，。；！？]?", narration)) else "v1"
        digest = hashlib.sha256((VOICE + "|windows-offline-phrases-" + phrase_version + "|" + narration).encode()).hexdigest()
        txt.write_text(narration, encoding="utf-8")
        # Reuse only the exact same voice/text cache, never stale narration.
        cached = digest_path.is_file() and digest_path.read_text() == digest and mp3.is_file() and srt.is_file()
        if not cached:
            synthesize_offline(narration, folder, f"voice-{i+1:02d}", mp3, srt)
            digest_path.write_text(digest)
        duration = math.ceil((duration_of(mp3) + .35) * FPS) / FPS
        local_cues = shifted_cues(srt, elapsed)
        if not local_cues or local_cues[-1][1] > elapsed + duration + .1:
            raise RuntimeError(f"{key} slide {i+1}: missing or out-of-range narration captions")
        cues.extend(local_cues)
        timeline.append({"slide":i+1, "title":slide[0], "start":round(elapsed,3), "end":round(elapsed+duration,3), "narration":narration})
        segment = folder / f"seg-{i+1:02d}.mp4"
        # Each slide lasts for its own narration; no equal-duration slideshow drift.
        run(["ffmpeg","-y","-hide_banner","-loglevel","error","-loop","1","-framerate",str(FPS),"-i",str(image),"-i",str(mp3),"-map","0:v","-map","1:a","-af","apad","-t",f"{duration:.6f}","-r",str(FPS),"-c:v","libx264","-tune","stillimage","-preset","veryfast","-crf","23","-pix_fmt","yuv420p","-c:a","aac","-ar","48000","-b:a","128k",str(segment)])
        segments.append(segment)
        elapsed += duration
    sheet = Image.new("RGB", (960, math.ceil(len(slides)/2)*270), BG)
    for i, path in enumerate(slides):
        sheet.paste(Image.open(path).resize((480,270),Image.Resampling.LANCZOS), ((i%2)*480,(i//2)*270))
    sheet.save(folder / "contact-sheet.jpg", quality=92)
    joined_srt = folder / "narration.srt"
    joined_srt.write_text("\n\n".join(f"{i+1}\n{srt_time(begin)} --> {srt_time(end)}\n{words}" for i,(begin,end,words) in enumerate(cues))+"\n",encoding="utf-8")
    (folder / "narration.txt").write_text(spec["narration"],encoding="utf-8")
    (folder / "timeline.json").write_text(json.dumps(timeline,ensure_ascii=False,indent=2),encoding="utf-8")
    concat = folder / "segments.txt"
    concat.write_text("\n".join(f"file '{p.as_posix()}'" for p in segments), encoding="utf-8")
    visual = folder / "visual-with-audio.mp4"
    run(["ffmpeg","-y","-hide_banner","-loglevel","error","-f","concat","-safe","0","-i",str(concat),"-c","copy",str(visual)])
    vtt = output / f"wanyutong-{key}-{release_date}.vtt"
    srt_to_vtt(joined_srt, vtt)
    out = output / f"wanyutong-{key}-{release_date}.mp4"
    temporary = output / f"wanyutong-{key}-{release_date}.tmp.mp4"
    sub = escape_filter_path(joined_srt)
    filt = f"[0:v]subtitles='{sub}':force_style='FontName=Microsoft JhengHei,FontSize=20,PrimaryColour=&H00FFFFFF,OutlineColour=&HAA000000,BorderStyle=3,Outline=1,Shadow=0,MarginV=24,Alignment=2'[v];[0:a]aresample=48000,loudnorm=I=-16:TP=-1.5:LRA=8[a]"
    run(["ffmpeg","-y","-hide_banner","-loglevel","error","-i",str(visual),"-filter_complex",filt,"-map","[v]","-map","[a]","-map_metadata","-1","-t",f"{elapsed:.3f}","-r",str(FPS),"-c:v","libx264","-profile:v","high","-level","4.2","-preset","medium","-crf","26","-pix_fmt","yuv420p","-colorspace","bt709","-color_primaries","bt709","-color_trc","bt709","-bsf:v","h264_metadata=video_full_range_flag=0:colour_primaries=1:transfer_characteristics=1:matrix_coefficients=1","-c:a","aac","-b:a","128k","-ar","48000","-movflags","+faststart",str(temporary)])
    os.replace(temporary, out)
    Image.open(slides[0]).save(output / f"wanyutong-{key}-{release_date}-poster.jpg",quality=90,optimize=True)
    return out


def build_guides(repo: Path, output: Path):
    guides = output / "guides"; guides.mkdir(parents=True, exist_ok=True)
    guide_specs = {
        "line-bot-add.jpg": ("群組：傳送 @選單", "LINE 群組不支援固定底部圖文選單", ["@選單 開聊天內六個功能入口", "手機私訊可直接點底部選單"]),
        "language-setting.jpg": ("語言設定，直接選", "@語言設定 開選語按鈕", ["快捷組合可直接套用，舊指令保留", "有效雙語設定會自動關閉多語模式"]),
        "group-confirmation.jpg": ("重要工作，人工確認", "請成員主動以文字回覆", ["收到翻譯不等於已讀或理解", "主管回看原文與回覆，再確認進度"]),
        "multilingual-reply.jpg": ("持續多語翻譯", "第一個目標可複製；其他語言逐一按鈕查看", ["24 小時快取，不會重新翻譯", "按鈕查看不會再次扣額度"]),
        "plan-and-activation.jpg": ("方案與開通", "在要開通的群組傳送 @方案", ["只用 Bot 回覆的官方連結", "付款後只開通或延長該群組"]),
        "secretary-status.jpg": ("AI 祕書狀態", "@祕書 狀態", ["先確認群組紀錄與摘要模式", "依回覆核對實際整理筆數"]),
    }
    mock = {"eyebrow": f"萬語通圖解｜{DISPLAY_DATE}", "slides": [None]}
    for name, slide in guide_specs.items():
        slide_image(guides / name, mock, 0, slide, repo / "assets" / "wanyutong-logo.jpg")


def main():
    global FPS
    ap=argparse.ArgumentParser(); ap.add_argument("--repo-root", type=Path, required=True); ap.add_argument("--work-dir", type=Path, required=True); ap.add_argument("--output-dir", type=Path, required=True); ap.add_argument("--release-date", default=RELEASE_DATE); ap.add_argument("--only", action="append", choices=list(VIDEOS)); ap.add_argument("--fps", type=int, choices=(30, 60), default=30)
    a=ap.parse_args(); FPS = a.fps
    missing = [name for name in ("ffmpeg", "ffprobe", "pwsh") if not shutil.which(name)]
    required = [
        a.repo_root / "assets" / "wanyutong-logo.jpg",
        Path(r"C:\Windows\Fonts\msjh.ttc"),
        Path(r"C:\Windows\Fonts\msjhbd.ttc"),
        Path(r"C:\Windows\Fonts\malgun.ttf"),
        Path(r"C:\Windows\Fonts\malgunbd.ttf"),
    ]
    missing += [str(p) for p in required if not p.is_file()]
    if missing:
        raise SystemExit("缺少影片產製必要元件：" + "、".join(missing))
    repo = a.repo_root.resolve()
    output = a.output_dir.resolve()
    work = a.work_dir.resolve()
    for destination in (output, work):
        if any(part.lower() == "onedrive" for part in destination.parts):
            raise SystemExit("Generated video files must be outside OneDrive: " + str(destination))
    work.mkdir(parents=True, exist_ok=True)
    build_guides(repo, output)
    built=[]
    for k,s in VIDEOS.items():
        if not a.only or k in a.only: built.append(build_one(k,s,repo,a.work_dir.resolve(),output,a.release_date))
    for p in built:
        probe=run(["ffprobe","-v","error","-show_entries","stream=codec_type,codec_name,width,height,r_frame_rate,pix_fmt,sample_rate:format=duration,size","-of","json",str(p)],True)
        print(p.name, probe.stdout)

if __name__ == "__main__": main()
