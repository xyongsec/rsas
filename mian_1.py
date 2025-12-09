import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import urllib3
import threading
from bs4 import BeautifulSoup
import json
import time

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSAS 综合管理工具 (自定义批量版)")
        self.root.geometry("900x900")

        # ================== 全局变量 ==================
        self.session = None
        self.is_logged_in = False
        self.timeout = 5
        # ============================================

        # 默认配置
        self.default_ip = "https://192.168.0.7"
        self.default_user = "admin"
        self.default_pass = "admin@123"
        self.default_proxy = "http://127.0.0.1:8083"

        self.setup_ui()

    def setup_ui(self):
        # ================= 配置区域 =================
        frame_config = ttk.LabelFrame(self.root, text="连接配置", padding=10)
        frame_config.pack(fill="x", padx=10, pady=5)

        # 第一行：IP 和 代理
        frame_row1 = ttk.Frame(frame_config)
        frame_row1.pack(fill="x", pady=2)

        ttk.Label(frame_row1, text="系统地址 (URL):").pack(side="left")
        self.entry_url = ttk.Entry(frame_row1, width=30)
        self.entry_url.insert(0, self.default_ip)
        self.entry_url.pack(side="left", padx=5)

        self.use_proxy_var = tk.BooleanVar()
        ttk.Checkbutton(frame_row1, text="启用代理", variable=self.use_proxy_var).pack(side="left", padx=10)

        self.entry_proxy = ttk.Entry(frame_row1, width=25)
        self.entry_proxy.insert(0, self.default_proxy)
        self.entry_proxy.pack(side="left", padx=5)

        # 第二行：账号密码
        frame_row2 = ttk.Frame(frame_config)
        frame_row2.pack(fill="x", pady=5)

        ttk.Label(frame_row2, text="用户名:").pack(side="left")
        self.entry_user = ttk.Entry(frame_row2, width=15)
        self.entry_user.insert(0, self.default_user)
        self.entry_user.pack(side="left", padx=5)

        ttk.Label(frame_row2, text="密码:").pack(side="left")
        self.entry_pass = ttk.Entry(frame_row2, width=15, show="*")
        self.entry_pass.insert(0, self.default_pass)
        self.entry_pass.pack(side="left", padx=5)

        ttk.Label(frame_row2, text="超时(秒):").pack(side="left", padx=(10, 2))
        self.entry_timeout = ttk.Entry(frame_row2, width=5)
        self.entry_timeout.insert(0, "10")
        self.entry_timeout.pack(side="left")

        # ================= 登录操作区域 =================
        frame_actions = ttk.Frame(frame_config)
        frame_actions.pack(fill="x", pady=10)

        self.btn_login = ttk.Button(frame_actions, text="1. 点击登录", command=self.thread_login)
        self.btn_login.pack(side="left", padx=5)

        self.lbl_status = ttk.Label(frame_actions, text="未登录", foreground="red")
        self.lbl_status.pack(side="left", padx=5)

        self.btn_get_list = ttk.Button(frame_actions, text="2. 获取任务列表", command=self.thread_get_list,
                                       state="disabled")
        self.btn_get_list.pack(side="left", padx=20)

        # ================= 任务下发区域 (Tab 改造) =================
        frame_task = ttk.LabelFrame(self.root, text="任务下发", padding=5)
        frame_task.pack(fill="x", padx=10, pady=5)

        self.task_notebook = ttk.Notebook(frame_task)
        self.task_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Tab 1: 单任务 ---
        self.tab_single = ttk.Frame(self.task_notebook)
        self.task_notebook.add(self.tab_single, text="单任务下发")

        frame_single_inner = ttk.Frame(self.tab_single, padding=10)
        frame_single_inner.pack(fill="x")

        ttk.Label(frame_single_inner, text="Web目标地址:").grid(row=0, column=0, sticky="w")
        self.entry_web_target = ttk.Entry(frame_single_inner, width=40)
        self.entry_web_target.insert(0, "http://www.baidu.com")
        self.entry_web_target.grid(row=0, column=1, padx=5, sticky="w")

        ttk.Label(frame_single_inner, text="任务名称:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_web_name = ttk.Entry(frame_single_inner, width=40)
        self.entry_web_name.insert(0, "Single_Task_001")
        self.entry_web_name.grid(row=1, column=1, padx=5, sticky="w", pady=5)

        self.btn_add_web = ttk.Button(frame_single_inner, text="下发单个任务", command=self.thread_add_web_task,
                                      state="disabled")
        self.btn_add_web.grid(row=2, column=1, sticky="w", padx=5, pady=10)

        # --- Tab 2: 批量任务 (修改版) ---
        self.tab_batch = ttk.Frame(self.task_notebook)
        self.task_notebook.add(self.tab_batch, text="自定义批量下发")

        frame_batch_inner = ttk.Frame(self.tab_batch, padding=10)
        frame_batch_inner.pack(fill="both", expand=True)

        # 说明文字
        lbl_guide = ttk.Label(frame_batch_inner,
                              text="格式说明：每行一条，使用英文分号(;)分隔。\n例如：\n淘宝项目, http://www.taobao.com\n百度扫描, http://www.baidu.com",
                              foreground="blue", justify="left")
        lbl_guide.pack(anchor="w", pady=(0, 5))

        # 输入区域
        self.txt_batch_data = scrolledtext.ScrolledText(frame_batch_inner, height=8, width=60)
        self.txt_batch_data.pack(fill="both", expand=True, padx=5, pady=5)

        # 按钮
        self.btn_batch_add = ttk.Button(frame_batch_inner, text="解析并批量下发", command=self.thread_batch_add,
                                        state="disabled")
        self.btn_batch_add.pack(anchor="e", pady=5)

        # ================= 结果列表区域 =================
        frame_table = ttk.LabelFrame(self.root, text="任务列表展示", padding=10)
        frame_table.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("id", "risk", "progress", "name")
        self.tree = ttk.Treeview(frame_table, columns=columns, show="headings", height=6)

        self.tree.heading("id", text="ID")
        self.tree.heading("risk", text="风险等级")
        self.tree.heading("progress", text="进度")
        self.tree.heading("name", text="任务名称")

        self.tree.column("id", width=60, anchor="center")
        self.tree.column("risk", width=80, anchor="center")
        self.tree.column("progress", width=80, anchor="center")
        self.tree.column("name", width=350)

        scrollbar = ttk.Scrollbar(frame_table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ================= 日志区域 =================
        frame_log = ttk.LabelFrame(self.root, text="运行日志", padding=10)
        frame_log.pack(fill="x", padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(frame_log, height=8, state='disabled')
        self.log_text.pack(fill="both", expand=True)

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def get_config(self):
        try:
            to = int(self.entry_timeout.get().strip())
        except:
            to = 10
        return {
            "url": self.entry_url.get().strip(),
            "user": self.entry_user.get().strip(),
            "pass": self.entry_pass.get().strip(),
            "proxy": self.entry_proxy.get().strip() if self.use_proxy_var.get() else None,
            "timeout": to
        }

    # ================= 线程入口 =================

    def thread_login(self):
        self.btn_login.config(state="disabled")
        self.log(">>> 开始登录流程...")
        config = self.get_config()
        t = threading.Thread(target=self.do_login, args=(config,))
        t.daemon = True
        t.start()

    def thread_get_list(self):
        if not self.session or not self.is_logged_in:
            self.log("[-] 请先登录！")
            return
        self.btn_get_list.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.log(">>> 开始获取列表...")
        config = self.get_config()
        t = threading.Thread(target=self.do_fetch_list, args=(config,))
        t.daemon = True
        t.start()

    def thread_add_web_task(self):
        """单任务添加线程"""
        if not self.session or not self.is_logged_in:
            self.log("[-] 请先登录！")
            return

        target_url = self.entry_web_target.get().strip()
        task_name = self.entry_web_name.get().strip()

        if not target_url or not task_name:
            messagebox.showwarning("警告", "Web地址和任务名称不能为空")
            return

        self.btn_add_web.config(state="disabled")
        self.log(f">>> 开始下发单任务: {task_name} -> {target_url}")
        config = self.get_config()

        def run():
            self.core_send_web_task(config, target_url, task_name)
            self.root.after(0, lambda: self.btn_add_web.config(state="normal"))

        t = threading.Thread(target=run)
        t.daemon = True
        t.start()

    def thread_batch_add(self):
        """批量任务添加线程 - 自定义名称版"""
        if not self.session or not self.is_logged_in:
            self.log("[-] 请先登录！")
            return

        raw_text = self.txt_batch_data.get("1.0", tk.END)
        lines = [line.strip() for line in raw_text.split('\n') if line.strip()]

        if not lines:
            messagebox.showwarning("提示", "请输入任务数据")
            return

        # 解析数据
        task_list = []
        task_list = []
        for line in lines:
            # [修改位置 2] 替换中文分号，并使用英文分号 ; 进行分割
            line = line.replace("；", ";")

            if ";" in line:
                parts = line.split(";", 1)  # 使用分号分割
                t_name = parts[0].strip()
                t_url = parts[1].strip()
                if t_name and t_url:
                    task_list.append((t_name, t_url))
                else:
                    self.log(f"[!] 跳过无效行: {line}")
            else:
                self.log(f"[!] 格式错误 (缺少分号): {line}")

        if not task_list:
            self.log("[-] 没有有效任务被解析，请检查格式。")
            return

        self.btn_batch_add.config(state="disabled")
        self.log(f">>> 解析成功，开始下发 {len(task_list)} 个任务...")
        config = self.get_config()

        def run_batch():
            success_count = 0
            for idx, (t_name, t_url) in enumerate(task_list):
                self.log(f"--- [任务 {idx + 1}/{len(task_list)}] ---")

                # 调用核心发送逻辑
                if self.core_send_web_task(config, t_url, t_name):
                    success_count += 1

                # 延时防止请求过快
                if idx < len(task_list) - 1:
                    time.sleep(1)

            self.log(f">>> 批量任务结束。成功: {success_count} / 总数: {len(task_list)}")
            self.root.after(0, lambda: self.btn_batch_add.config(state="normal"))

        t = threading.Thread(target=run_batch)
        t.daemon = True
        t.start()

    # ================= 业务逻辑 =================

    def do_login(self, config):
        base_url = config['url']
        proxies = {}
        if config['proxy']:
            proxies = {"http": config['proxy'], "https": config['proxy']}

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "Origin": base_url,
            "Upgrade-Insecure-Requests": "1"
        }
        session = requests.Session()
        session.headers.update(headers)
        if proxies: session.proxies.update(proxies)

        try:
            self.log("[1/2] 获取Token...")
            try:
                session.get(f"{base_url}/accounts/login/?next=/", verify=False, timeout=config['timeout'])
            except Exception as e:
                self.log(f"[-] 连接失败: {e}")
                self.root.after(0, lambda: self.reset_login_ui(False))
                return

            token = session.cookies.get('csrftoken')
            if not token:
                self.log("[-] 未获取到CSRF Token")
                self.root.after(0, lambda: self.reset_login_ui(False))
                return

            self.log("[2/2] 验证账号...")
            resp = session.post(
                f"{base_url}/accounts/login_view/",
                data={"username": config['user'], "password": config['pass'], "csrfmiddlewaretoken": token},
                headers={"Referer": f"{base_url}/accounts/login/?next=/"},
                verify=False, allow_redirects=False, timeout=config['timeout']
            )

            if resp.status_code == 302:
                self.log("[+] 登录成功")
                self.session = session
                self.is_logged_in = True
                self.root.after(0, lambda: self.reset_login_ui(True))
            else:
                self.log(f"[-] 登录失败: {resp.status_code}")
                self.root.after(0, lambda: self.reset_login_ui(False))

        except Exception as e:
            self.log(f"[-] 异常: {e}")
            self.root.after(0, lambda: self.reset_login_ui(False))

    def do_fetch_list(self, config):
        base_url = config['url']
        try:
            csrftoken = self.session.cookies.get('csrftoken')
            self.log("[*] 请求任务列表...")
            resp = self.session.post(
                f"{base_url}/list/getList",
                data=f"csrfmiddlewaretoken={csrftoken}&ip=&task_name=&domain=&task_status=&image_tag=&rs_template=&tpl=&protect_level=S1A1G1&account=&time_start_scan=&time_end_scan=&exp_task=all&task_type=&page=1&page_count=10&exp_task=all&bvs_template=&protect_level=",
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRFToken": csrftoken,
                    "Referer": f"{base_url}/list/",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                verify=False, timeout=config['timeout']
            )

            if resp.status_code == 200:
                self.root.after(0, lambda: self.parse_and_display(resp.text))
            else:
                self.log(f"[-] 获取列表失败: {resp.status_code}")
                if resp.status_code in [401, 403]:
                    self.is_logged_in = False
                    self.root.after(0, lambda: self.reset_login_ui(False))
        except Exception as e:
            self.log(f"[-] 获取列表异常: {e}")
        finally:
            self.root.after(0, lambda: self.btn_get_list.config(state="normal"))

    def core_send_web_task(self, config, target_url, task_name):
        """
        核心发送函数
        """
        base_url = config['url']
        try:
            csrftoken = self.session.cookies.get('csrftoken')

            # 构建 protocalarray (动态填入 target)
            protocal_data = [{
                "target": target_url,
                "protocal_type": "auto",
                "protocal_name": "",
                "protocal_pwd": "",
                "login_scan_type": "no",
                "cookies": "",
                "cookie_type": "set_cookie",
                "black_links": "",
                "wihte_links": "",
                "form_switch": "no",
                "form_cont": "no",
                "form_str": ""
            }]
            protocal_json_str = json.dumps(protocal_data)

            # 保持原始请求体所有字段
            payload = {
                "csrfmiddlewaretoken": csrftoken,
                "target_count": "1",
                "config_task": "taskname",
                "task_config": "",
                "task_target": target_url,
                "task_name": task_name,
                "scan_method": "1",
                "subdomains_scan": "0",
                "subdomains": "",
                "exec": "immediate",
                "exec_timing_date": "2025-12-09 15:06:01",
                "exec_everyday_time": "00:00",
                "exec_everyweek_day": "1",
                "exec_everyweek_time": "00:00",
                "exec_emonthdate_day": "1",
                "exec_emonthdate_time": "00:00",
                "exec_emonthweek_pre": "1",
                "exec_emonthweek_day": "1",
                "exec_emonthweek_time": "00:00",
                "tpl": "0",
                "ws_proxy_type": "HTTP",
                "ws_proxy_auth": "Basic",
                "ws_proxy_server": "",
                "ws_proxy_port": "",
                "ws_proxy_username": "",
                "ws_proxy_password": "",
                "cron_range": "",
                "dispatchLevel": "2",
                "target_description": "",
                "report_type_html": "html",
                "summarizeReport": "yes",
                "oneSiteReport": "yes",
                "sum_report_tpl": "201",
                "site_report_tpl": "301",
                "sendReport_type": "html",
                "email_address": "",
                "plugin_threads": "20",
                "webscan_timeout": "30",
                "page_encoding": "0",
                "coding": "UTF8",
                "login_ifuse": "yes",
                "user_agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN; rv:1.9.2.4) Gecko/20100611 Firefox/3.6.4",
                "header_count": "0",
                "header_key": "",
                "header_value": "",
                "dir_level": "1",
                "dir_limit": "3",
                "filetype_to_check_backup": "shtml,php,jsp,asp,aspx",
                "backup_filetype": "bak,old",
                "text2": "",
                "weak_count": "11",
                "weak_user": "",
                "weak_pwd": "",
                "weak_user_11": "Administrator",
                "weak_pwd_11": "Administrator",
                "weak_user_10": "test",
                "weak_pwd_10": "abc123",
                "weak_user_9": "test",
                "weak_pwd_9": "123456",
                "weak_user_8": "root",
                "weak_pwd_8": "",
                "weak_user_7": "root",
                "weak_pwd_7": "123456",
                "weak_user_6": "test",
                "weak_pwd_6": "test",
                "weak_user_5": "root",
                "weak_pwd_5": "root",
                "weak_user_4": "admin",
                "weak_pwd_4": "abc123",
                "weak_user_3": "admin",
                "weak_pwd_3": "admin888",
                "weak_user_2": "admin",
                "weak_pwd_2": "123456",
                "weak_user_1": "admin",
                "weak_pwd_1": "admin",
                "scan_type": "0",
                "dir_files_limit": "30",
                "dir_depth_limit": "15",
                "scan_link_limit": "10000",
                "file_exts": "png, gif, jpg, mp4, mp3, mng, pct, bmp, jpeg, pst, psp, ttf, tif, tiff, ai, drw, wma, ogg, wav, ra, aac, mid, au, aiff, dxf, eps, ps, svg, 3gp, asf, asx, avi, mov, mpg, qt, rm, wmv, m4a, bin, xls, xlsx, ppt, pptx, doc, docx, odt, ods, odg, odp, exe, zip, rar, tar, gz, iso, rss, pdf, txt, dll, ico, gz2, apk, crt, woff, map, woff2, webp, less, dmg, bz2, otf, swf, flv, mpeg, dat, xsl, csv, cab, exif, wps, m4v, rmvb, msi, deb, rpm, terrain",
                "case_sensitive": "1",
                "if_javascript": "1",
                "if_repeat": "2",
                "protocalarray": protocal_json_str
            }

            headers = {
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36",
                "Referer": f"{base_url}/task/index/8",
                "Origin": base_url
            }

            self.log(f"[*] 正在提交任务: {task_name} -> {target_url}")
            resp = self.session.post(
                f"{base_url}/task/web_newtask/",
                data=payload, headers=headers, verify=False, timeout=config['timeout']
            )

            if resp.status_code == 200:
                self.log(f"[+] 任务下发成功")
                return True
            else:
                self.log(f"[-] 任务下发失败: {resp.status_code}")
                return False

        except Exception as e:
            self.log(f"[-] 下发任务异常: {e}")
            return False

    def reset_login_ui(self, success):
        self.btn_login.config(state="normal")
        if success:
            self.lbl_status.config(text="已登录", foreground="green")
            self.btn_get_list.config(state="normal")
            self.btn_add_web.config(state="normal")
            self.btn_batch_add.config(state="normal")
        else:
            self.lbl_status.config(text="登录失败", foreground="red")
            self.btn_get_list.config(state="disabled")
            self.btn_add_web.config(state="disabled")
            self.btn_batch_add.config(state="disabled")

    def parse_and_display(self, html_content):
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            rows = soup.find_all('tr', class_=['even', 'odd'])
            if not rows:
                self.log("[-] 数据为空或解析失败")
                return

            count = 0
            for row in rows:
                try:
                    cols = row.find_all('td')
                    if len(cols) < 7: continue
                    task_id = cols[1].get_text(strip=True)
                    name_tag = cols[2].find('a')
                    task_name = name_tag.get_text(strip=True) if name_tag else ""
                    risk_img = cols[2].find('img')
                    risk_level = risk_img.get('title') if risk_img else ""
                    progress = cols[6].get_text(strip=True)
                    self.tree.insert("", "end", values=(task_id, risk_level, progress, task_name))
                    count += 1
                except:
                    continue
            self.log(f"[+] 列表刷新完毕，共 {count} 条")
        except Exception as e:
            self.log(f"[-] HTML解析错误: {e}")
        self.btn_get_list.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()