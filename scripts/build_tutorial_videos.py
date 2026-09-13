from __future__ import annotations

import argparse
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
VOICE = "zh-TW-HsiaoChenNeural"

VIDEOS = {
    "line-bot-tutorial": {
        "eyebrow": "LINE 群組翻譯｜最新版",
        "title": "一句話，讓多國團隊同步理解",
        "narration": """萬語通把多國溝通留在同一個 LINE 群組。第一次使用，傳送小老鼠新手教學，或小老鼠說明，查看正確指令；小老鼠語言可查看目前設定，小老鼠支援語言可查看即時清單。要使用雙語模式，傳送小老鼠語言設定，空格，繁體中文，空格，印尼文。設定後直接傳一般訊息，系統會持續雙向翻譯。要同時顯示多種語言，傳送小老鼠多語，空格，繁體中文，空格，英文，空格，菲律賓語。萬語通總共支援三十六種語言；持續多語最多可以同時設定八種。多語設定會持續套用後續一般訊息，而且群組所有成員看到同一份結果。離開多語有兩種方式。傳送小老鼠多語，空格，關閉，回到原本雙語；或直接送出一組有效的小老鼠語言設定，改成新的雙語並自動關閉多語。格式或語言無效時，原設定不會被意外改掉。免費版的中文、英文、日文與韓文不限次數，其他語言每日五十則；付費方案再依方案提供語音、圖片文字辨識與摘要等功能。翻譯或摘要可能有誤，高風險內容仍請人工複核。免費主機冷啟動、四二九、額度用完或排程延遲屬黃色營運事件，不等同遭到駭客入侵。現在就在群組傳送小老鼠說明。""",
        "slides": [
            ("一句話，多國同步", "不換 App｜不拆群組｜同一份結果", ["所有成員看見相同翻譯", "適合工廠、照護、餐飲與跨國團隊"]),
            ("第一次使用", "先確認最新指令與目前設定", ["@新手教學｜@說明｜@語言", "@支援語言：查看即時清單"]),
            ("雙語持續翻譯", "設定一次，後續一般訊息直接翻譯", ["@語言設定 繁體中文 印尼文", "有效設定會自動關閉多語模式"]),
            ("多語持續翻譯", "總支援 36 種；持續多語最多同時 8 種", ["@多語 繁體中文 英文 菲律賓語", "全群組共用同一份多語結果"]),
            ("兩種離開方式", "少一步，也不容易卡在舊模式", ["@多語 關閉 → 回原雙語", "有效 @語言設定 → 新雙語並自動關閉"]),
            ("免費也能開始", "中文／英文／日文／韓文不限次數", ["其他語言每日 50 則", "付費方案另有語音、圖片 OCR、摘要等功能"]),
            ("黃色營運事件 ≠ 遭駭", "冷啟動、429、額度用完、排程延遲", ["翻譯與摘要可能有誤", "工安、醫療、金額、合約仍須人工複核"]),
            ("現在就試一次", "在群組傳送 @說明", ["依 Bot 回覆操作", "重要內容請人工確認"]),
        ],
    },
    "secretary-tutorial": {
        "eyebrow": "AI 祕書｜付費群組功能",
        "title": "群組訊息，不該翻完就消失",
        "narration": """萬語通 AI 秘書，整理同一個付費群組內已留下的工作紀錄。它可以只記錄、不自動插話；自動回覆預設關閉，避免干擾現場溝通。小老鼠祕書與小老鼠秘書兩種寫法都可以。第一次使用，傳送小老鼠祕書，空格，說明，查看可用功能。再傳送小老鼠祕書，空格，狀態，確認翻譯、紀錄、摘要、日報、自動回覆與最近紀錄。需要快速整理時，傳送小老鼠祕書，空格，摘要。系統會理解群組內的多語紀錄，並以繁體中文整理重點。需要交班資料時，傳送小老鼠祕書，空格，報表。摘要依方案整理近期紀錄，官網目前標示最多可整理最近三百筆。AI 秘書協助整理，不取代主管判斷。翻譯或摘要可能有誤，高風險內容仍要回看原始紀錄並人工確認。免費主機冷啟動、四二九、額度用完或排程延遲屬黃色營運事件，不等同遭到駭客入侵。現在就在已開通的群組傳送小老鼠祕書，空格，說明。""",
        "slides": [
            ("翻譯之外，留下工作脈絡", "AI 祕書是付費群組功能", ["只處理該群組紀錄", "不串接私人聊天或其他群組"]),
            ("安靜地記錄", "可只記錄，不自動插話", ["自動回覆預設關閉", "降低群組干擾"]),
            ("先看說明與狀態", "@祕書 與 @秘書 兩種寫法皆可", ["@祕書 說明", "@祕書 狀態"]),
            ("一鍵抓重點", "理解多語紀錄，以繁中整理", ["@祕書 摘要", "待辦｜風險｜交班重點"]),
            ("交班與留存", "依目前方案整理近期紀錄", ["@祕書 報表", "官網標示最多最近 300 筆"]),
            ("AI 祕書整理，主管確認", "高風險內容一定回看原始紀錄", ["工安｜醫療｜付款｜金額｜合約", "不以摘要取代人工判斷"]),
            ("黃色營運事件 ≠ 遭駭", "冷啟動、429、額度用完、排程延遲", ["翻譯與摘要可能有誤", "真正資安事件才使用紅色即時警報"]),
            ("從說明開始", "在已開通群組傳送 @祕書 說明", ["確認狀態，再建立摘要與報表", "重要內容請人工確認"]),
        ],
    },
    "activation-flow": {
        "eyebrow": "方案與開通｜安全流程",
        "title": "付款，只開通你指定的群組",
        "narration": """萬語通免費版零元，中文、英文、日文與韓文不限次數，其他語言每日五十則。需要完整付費功能時，目前方案是月費版九十九元，三十天；半年版四百九十九元，一百八十天；一年版七百九十九元，四百二十天；尊爵版兩千五百元，每群組永久買斷。開通只有三步。先加入萬語通 LINE 官方帳號，再把 Bot 加進要使用的群組。接著在那個群組傳送小老鼠方案，只使用 Bot 回覆的官方付款連結。完成正式付款後，系統依付款回呼，只開通或延長該群組。不要使用陌生人私訊或轉傳的付款網址。開通後，可依方案使用完整語言、語音、圖片文字辨識、AI 秘書摘要、日報、紀錄查詢、統計、報表與匯出。付款金額、使用期間與是否續扣，以送出前的正式訂購畫面為準。若付款成功超過五分鐘仍未開通，請在群組傳送小老鼠客服查核，不要再次付款。翻譯或摘要可能有誤，高風險內容仍請人工複核。免費主機冷啟動、四二九、額度用完或排程延遲屬黃色營運事件，不等同遭到駭客入侵。""",
        "slides": [
            ("只開通指定群組", "方案、付款與群組綁定", ["不跨群組自動開通", "先確認群組，再進入官方付款頁"]),
            ("免費版 NT$0", "加入即可開始", ["中／英／日／韓不限次數", "其他語言每日 50 則"]),
            ("現行付費方案", "每個群組分開計算", ["月費 NT$99／30 天｜半年 NT$499／180 天", "一年 NT$799／420 天｜尊爵 NT$2500／永久"]),
            ("第一步：指定群組", "加入官方帳號，把 Bot 放進要使用的群組", ["第二步：在該群組傳送 @方案", "只使用 Bot 回覆的官方連結"]),
            ("第三步：完成正式付款", "付款回呼只開通或延長該群組", ["不信任陌生私訊或轉傳網址", "金額、期間、續扣以訂購畫面為準"]),
            ("開通後依方案使用", "完整語言、語音、圖片 OCR、AI 秘書", ["摘要｜日報｜查詢｜統計｜報表｜匯出", "重要內容仍須人工複核"]),
            ("付款後五分鐘仍未開通？", "用 @客服 查核，不要再次付款", ["保留正式訂單資訊", "勿在群組公開付款或個人資料"]),
            ("黃色營運事件 ≠ 遭駭", "冷啟動、429、額度用完、排程延遲", ["翻譯與摘要可能有誤", "高風險內容仍須人工複核"]),
        ],
    },
}


def run(args: list[str], capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture)


def fnt(size: int, bold=False):
    p = Path(r"C:\Windows\Fonts\msjhbd.ttc" if bold else r"C:\Windows\Fonts\msjh.ttc")
    return ImageFont.truetype(str(p), size)


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
    if "方案" in title or "付款" in title or "免費" in title or "開通" in title or "指定群組" in title:
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
    for line in wrap(d, title, fnt(62, True), 920):
        d.text((160, y), line, font=fnt(66, True), fill=TEXT); y += 88
    y += 12
    for line in wrap(d, sub, fnt(33), 910):
        d.text((164, y), line, font=fnt(36), fill=MUTED); y += 55
    y += 28
    for b in bullets:
        d.rounded_rectangle((160, y + 4, 190, y + 34), radius=8, fill=GREEN)
        for line in wrap(d, b, fnt(30, True), 850):
            d.text((220, y), line, font=fnt(30, True), fill="#e9f7ef"); y += 46
        y += 25
    draw_visual(d, title, sub)
    d.text((160, 962), "依 2026-09-14 官網與正式功能重製｜重要資訊請人工確認", font=fnt(23), fill="#718091")
    im.save(path, quality=96)


def srt_to_vtt(srt: Path, vtt: Path):
    text = srt.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    text = re.sub(r"(?<=\d),(?=\d{3})", ".", text).strip()
    vtt.write_text("WEBVTT\n\n" + text + "\n", encoding="utf-8")


def escape_filter_path(p: Path):
    return str(p).replace("\\", "/").replace(":", r"\:").replace("'", r"\'")


def build_one(key: str, spec: dict, repo: Path, work: Path):
    folder = work / key; folder.mkdir(parents=True, exist_ok=True)
    assets = repo / "assets"; logo = assets / "wanyutong-logo.jpg"
    slides = []
    for i, s in enumerate(spec["slides"]):
        p = folder / f"slide-{i+1:02d}.png"; slide_image(p, spec, i, s, logo); slides.append(p)
    sheet = Image.new("RGB", (960, 4 * 270), BG)
    for i, p in enumerate(slides):
        thumb=Image.open(p).resize((480,270),Image.Resampling.LANCZOS)
        sheet.paste(thumb, ((i%2)*480,(i//2)*270))
    sheet.save(folder / "contact-sheet.jpg", quality=90)
    txt, mp3, srt = folder / "narration.txt", folder / "narration.mp3", folder / "narration.srt"
    txt.write_text(spec["narration"], encoding="utf-8")
    run([sys.executable, "-m", "edge_tts", "--file", str(txt), "--voice", VOICE, "--rate=-2%", "--pitch=-1Hz", "--write-media", str(mp3), "--write-subtitles", str(srt)])
    probe = run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(mp3)], True)
    audio_dur = float(json.loads(probe.stdout)["format"]["duration"])
    total = audio_dur + 2.0; overlap = 0.65; segdur = (total + overlap * (len(slides)-1)) / len(slides)
    segments = []
    for i, p in enumerate(slides):
        out = folder / f"seg-{i+1:02d}.mp4"
        z = "min(zoom+0.00010,1.025)" if i % 2 == 0 else "if(eq(on,0),1.025,max(zoom-0.00010,1.0))"
        vf = f"zoompan=z='{z}':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d={math.ceil(segdur*FPS)}:s={W}x{H}:fps={FPS},format=yuv420p"
        run(["ffmpeg","-y","-hide_banner","-loglevel","error","-loop","1","-i",str(p),"-vf",vf,"-t",f"{segdur:.3f}","-r",str(FPS),"-an","-c:v","libx264","-preset","veryfast","-crf","19","-pix_fmt","yuv420p",str(out)])
        segments.append(out)
    inputs=[]
    for p in segments: inputs += ["-i", str(p)]
    fc=[]; last="[0:v]"; offset=segdur-overlap
    for i in range(1,len(segments)):
        out=f"[v{i}]"; fc.append(f"{last}[{i}:v]xfade=transition=fade:duration={overlap}:offset={offset:.3f}{out}"); last=out; offset += segdur-overlap
    visual = folder / "visual.mp4"
    run(["ffmpeg","-y","-hide_banner","-loglevel","error",*inputs,"-filter_complex",";".join(fc),"-map",last,"-t",f"{total:.3f}","-an","-c:v","libx264","-preset","veryfast","-crf","19","-pix_fmt","yuv420p",str(visual)])
    vtt = assets / f"wanyutong-{key}-20260914.vtt"; srt_to_vtt(srt, vtt)
    out = assets / f"wanyutong-{key}-20260914.mp4"; temp_out = assets / f"wanyutong-{key}-20260914.tmp.mp4"
    sub = escape_filter_path(srt)
    final_crf = "28" if key == "line-bot-tutorial" else "26"
    filt = f"[0:v]subtitles='{sub}':force_style='FontName=Microsoft JhengHei,FontSize=15,PrimaryColour=&H00FFFFFF,OutlineColour=&HAA000000,BorderStyle=3,Outline=1,Shadow=0,MarginV=34,Alignment=2'[v];[1:a]aresample=48000,loudnorm=I=-16:TP=-1.5:LRA=8[a]"
    run(["ffmpeg","-y","-hide_banner","-loglevel","error","-i",str(visual),"-i",str(mp3),"-filter_complex",filt,"-map","[v]","-map","[a]","-map_metadata","-1","-t",f"{total:.3f}","-r",str(FPS),"-c:v","libx264","-profile:v","high","-level","4.2","-preset","medium","-crf",final_crf,"-pix_fmt","yuv420p","-colorspace","bt709","-color_primaries","bt709","-color_trc","bt709","-bsf:v","h264_metadata=video_full_range_flag=0:colour_primaries=1:transfer_characteristics=1:matrix_coefficients=1","-c:a","aac","-b:a","128k","-ar","48000","-movflags","+faststart",str(temp_out)])
    os.replace(temp_out, out)
    poster = assets / f"wanyutong-{key}-20260914-poster.jpg"
    Image.open(slides[0]).save(poster, quality=88, optimize=True)
    return out


def build_guides(repo: Path):
    guides = repo / "assets" / "guides"; guides.mkdir(parents=True, exist_ok=True)
    guide_specs = {
        "line-bot-add.jpg": ("把 Bot 加入工作群組", "主管建立群組後，加入萬語通官方 Bot", ["不需要移轉成員資料", "先傳送 @新手教學"]),
        "language-setting.jpg": ("設定雙語模式", "@語言設定 繁體中文 印尼文", ["有效設定會持續翻譯", "也會自動關閉多語模式"]),
        "group-confirmation.jpg": ("全群組共用設定", "主管、員工 A、員工 B 看見同一份結果", ["不是每人私下不同畫面", "設定不會被其他成員意外消耗"]),
        "multilingual-reply.jpg": ("持續多語翻譯", "總支援 36 種；最多同時 8 種", ["@多語 繁體中文 英文 菲律賓語", "直到關閉或改成有效雙語設定"]),
        "plan-and-activation.jpg": ("方案與開通", "在要開通的群組傳送 @方案", ["只用 Bot 回覆的官方連結", "付款後只開通或延長該群組"]),
        "secretary-status.jpg": ("AI 祕書狀態", "@祕書 狀態", ["確認紀錄、摘要、日報與自動回覆", "高風險內容仍由主管人工確認"]),
    }
    mock = {"eyebrow": "萬語通圖解｜2026-09-14", "slides": [None]}
    for name, slide in guide_specs.items():
        slide_image(guides / name, mock, 0, slide, repo / "assets" / "wanyutong-logo.jpg")


def main():
    global FPS
    ap=argparse.ArgumentParser(); ap.add_argument("--repo-root", type=Path, required=True); ap.add_argument("--work-dir", type=Path, required=True); ap.add_argument("--only", choices=list(VIDEOS)); ap.add_argument("--fps", type=int, choices=(30, 60), default=30)
    a=ap.parse_args(); FPS = a.fps
    missing = [name for name in ("ffmpeg", "ffprobe") if not shutil.which(name)]
    required = [a.repo_root / "assets" / "wanyutong-logo.jpg", Path(r"C:\Windows\Fonts\msjh.ttc"), Path(r"C:\Windows\Fonts\msjhbd.ttc")]
    missing += [str(p) for p in required if not p.is_file()]
    if missing:
        raise SystemExit("缺少影片產製必要元件：" + "、".join(missing))
    try:
        import edge_tts  # noqa: F401
    except ImportError as exc:
        raise SystemExit("缺少 edge-tts：請先安裝後再重跑。") from exc
    a.work_dir.mkdir(parents=True, exist_ok=True)
    build_guides(a.repo_root.resolve())
    built=[]
    for k,s in VIDEOS.items():
        if not a.only or a.only==k: built.append(build_one(k,s,a.repo_root.resolve(),a.work_dir.resolve()))
    for p in built:
        probe=run(["ffprobe","-v","error","-show_entries","stream=codec_type,codec_name,width,height,r_frame_rate,pix_fmt,sample_rate:format=duration,size","-of","json",str(p)],True)
        print(p.name, probe.stdout)

if __name__ == "__main__": main()
