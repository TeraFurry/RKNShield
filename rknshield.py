# -*- coding: utf-8 -*-
"""
RKNShield - консольная программа для Windows (запускать от администратора).

Что умеет:
  1. Ищет российские корневые сертификаты ПО СОДЕРЖИМОМУ (кто выдал, кому выдан, отпечаток),
     а не только по названию.
  2. Удаляет их и вносит в "Недоверенные сертификаты" Windows (чёрный список).
  3. Блокирует запуск русских браузеров (Яндекс, Atom, Спутник, Амиго, Комета).
  4. Защищает свою папку и ставит "сторожа", который каждые 30 минут всё перепроверяет.
  5. Показывает, что заблокировано, и умеет всё ОТМЕНИТЬ.
"""
import sys, os, json, ctypes, subprocess, shutil, datetime, base64, tempfile, re

try:
    import winreg
except ImportError:
    print("Эта программа работает только в Windows.")
    sys.exit(1)

# ----------------------------------------------------------------------------
# НАСТРОЙКИ (можно менять)
# ----------------------------------------------------------------------------
APP_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "RKNShield")
BACKUP_DIR = os.path.join(APP_DIR, "backup")
STATE_FILE = os.path.join(APP_DIR, "state.json")
LOG_FILE = os.path.join(APP_DIR, "log.txt")
TASKS = ["RKNShieldGuardTimer", "RKNShieldGuardBoot"]
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
BLOCK_CMD = r"C:\Windows\System32\cmd.exe /c exit"
MARK = "RKNShield"  # метка: "этот блок поставила наша программа"

# Слова, по которым ищем сертификат ВНУТРИ (владелец / кто выдал).
# Нашли в Интернете: владелец записан как
#   "The Ministry of Digital Development and Communications",
#   имена: "Russian Trusted Root CA", "Russian Trusted Sub CA".
CERT_WORDS = [
    "russian trusted",
    "ministry of digital development",
    "минцифры",
    "министерство цифрового развития",
]
# Отпечатки (SHA-1), найденные в Интернете (страница Сбера для разработчиков).
KNOWN_SHA1 = {
    "8FF915CCAB7BC16F8C5C8099D53E0E115B3AEC2F",
    "335D43F53451B781535FF3882DF713D3C14F8A01",
}

# Имена exe-файлов браузеров, которые блокируем всегда.
BROWSER_NAMES = [
    "browser.exe",          # Яндекс Браузер
    "yandex.exe",
    "yandexbrowser.exe",
    "service_update.exe",   # обновлятор Яндекса
    "atom.exe",             # Atom от VK (так же назывался редактор GitHub Atom)
    "amigo.exe",
    "sputnik.exe",
    "kometa.exe",
]
# Для поиска браузеров по данным ВНУТРИ exe (компания/продукт):
VENDOR_RE = r"Yandex|Яндекс|Mail\.?Ru|\bVK\b|ВКонтакте|Rostelecom|Ростелеком"
BROWSER_RE = r"browser|браузер|atom|amigo|sputnik|спутник|kometa|комета"

# Эти имена НЕЛЬЗЯ блокировать никогда (сломается Windows или нужные программы).
NEVER_BLOCK = {
    "explorer.exe", "cmd.exe", "powershell.exe", "svchost.exe", "rundll32.exe",
    "conhost.exe", "taskmgr.exe", "winlogon.exe", "csrss.exe", "lsass.exe",
    "services.exe", "regedit.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "python.exe", "pythonw.exe", "schtasks.exe", "certutil.exe", "icacls.exe",
}

# ----------------------------------------------------------------------------
# Мелкие помощники
# ----------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate():
    """Перезапускаем себя с правами администратора."""
    if getattr(sys, "frozen", False):
        params = " ".join('"%s"' % a for a in sys.argv[1:])
    else:
        params = " ".join('"%s"' % a for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)


def log(text):
    os.makedirs(APP_DIR, exist_ok=True)
    line = "%s  %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(cmd):
    """Запустить обычную команду. Вернуть (код, текст)."""
    r = subprocess.run(cmd, capture_output=True)
    return r.returncode, r.stdout.decode("cp866", "replace") + r.stderr.decode("cp866", "replace")


def run_ps(script):
    """Запустить кусок PowerShell через временный файл. Вернуть (код, текст)."""
    fd, path = tempfile.mkstemp(suffix=".ps1")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write("[Console]::OutputEncoding=[Text.Encoding]::UTF8\n" + script)
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def as_list(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    return data if isinstance(data, list) else [data]


def load_state():
    st = {"certs": {}, "blocked": [], "protected": False, "guard": False}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            st.update(json.load(f))
    except Exception:
        pass
    return st


def save_state(st):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)


def ask(text):
    return input(text).strip().lower() in ("д", "да", "y", "yes")


# ----------------------------------------------------------------------------
# СЕРТИФИКАТЫ
# ----------------------------------------------------------------------------
CERT_PS = r'''
$out = @()
foreach ($loc in "LocalMachine","CurrentUser") {
  foreach ($st in "Root","CA","AuthRoot") {
    $p = "Cert:\$loc\$st"
    if (Test-Path $p) {
      foreach ($c in (Get-ChildItem $p)) {
        $out += [pscustomobject]@{
          Loc=$loc; Store=$st; Subject=$c.Subject; Issuer=$c.Issuer;
          Thumb=$c.Thumbprint; NotAfter=$c.NotAfter.ToString("yyyy-MM-dd");
          Raw=[Convert]::ToBase64String($c.RawData)
        }
      }
    }
  }
}
if ($out.Count -gt 0) { @($out) | ConvertTo-Json -Compress } else { "[]" }
'''


def looks_russian(c):
    if (c.get("Thumb") or "").upper() in KNOWN_SHA1:
        return True
    text = ((c.get("Subject") or "") + " " + (c.get("Issuer") or "")).lower()
    return any(w in text for w in CERT_WORDS)


def scan_certs():
    """Вернуть найденные сертификаты, сгруппированные по отпечатку."""
    _, out = run_ps(CERT_PS)
    groups = {}
    for c in as_list(out):
        if not looks_russian(c):
            continue
        key = c["Thumb"].upper()
        g = groups.setdefault(key, {
            "thumb": key, "subject": c["Subject"], "issuer": c["Issuer"],
            "until": c["NotAfter"], "raw": c["Raw"], "places": []})
        g["places"].append([c["Loc"], c["Store"]])
    return list(groups.values())


def show_certs(items):
    for i, it in enumerate(items, 1):
        print("\n[%d] Кому выдан: %s" % (i, it["subject"]))
        print("    Кем выдан:  %s" % it["issuer"])
        print("    Отпечаток:  %s" % it["thumb"])
        print("    Действует до: %s" % it["until"])
        print("    Лежит тут:  %s" % ", ".join("%s\\%s" % tuple(p) for p in it["places"]))


def kill_certs(items, st):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for it in items:
        cer = os.path.join(BACKUP_DIR, it["thumb"] + ".cer")
        with open(cer, "wb") as f:
            f.write(base64.b64decode(it["raw"]))
        # 1) сначала в чёрный список (общий и для текущего пользователя)
        run(["certutil", "-addstore", "-f", "Disallowed", cer])
        run(["certutil", "-user", "-addstore", "-f", "Disallowed", cer])
        # 2) потом удаляем из всех мест, где нашли
        for loc, store in it["places"]:
            run_ps('Remove-Item -Path "Cert:\\%s\\%s\\%s" -Force' % (loc, store, it["thumb"]))
        st["certs"][it["thumb"]] = {
            "subject": it["subject"], "places": it["places"], "backup": cer,
            "when": datetime.datetime.now().isoformat(timespec="seconds")}
        log("Сертификат удалён и в чёрном списке: %s [%s]" % (it["subject"], it["thumb"]))
    save_state(st)


def cmd_find():
    print("\nИщу сертификаты...")
    items = scan_certs()
    if not items:
        print("Российских сертификатов не найдено.")
        return []
    print("НАЙДЕНО: %d шт." % len(items))
    show_certs(items)
    return items


def cmd_kill():
    items = cmd_find()
    if not items:
        return
    print("\nЕсли Windows спросит подтверждение на удаление - нажми 'Да'.")
    if not ask("Удалить и внести в чёрный список? (д/н): "):
        print("Отменено.")
        return
    st = load_state()
    kill_certs(items, st)
    left = scan_certs()
    if left:
        print("Осталось неудалённых: %d (возможно, ты нажал 'Нет' в окне Windows)." % len(left))
    else:
        print("Готово. Сертификатов не осталось, они в чёрном списке.")


# ----------------------------------------------------------------------------
# БРАУЗЕРЫ (блок запуска через реестр Windows)
# ----------------------------------------------------------------------------
EXE_PS = r'''
$dirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData) |
        Where-Object { $_ -and (Test-Path $_) }
$res = foreach ($f in (Get-ChildItem -Path $dirs -Recurse -Depth 5 -Filter *.exe -ErrorAction SilentlyContinue)) {
  $v = $f.VersionInfo
  if ("$($v.CompanyName) $($v.ProductName)" -match '__VENDOR__') {
    [pscustomobject]@{ Name=$f.Name; Path=$f.FullName; Company=$v.CompanyName; Product=$v.ProductName; Desc=$v.FileDescription }
  }
}
if ($res) { @($res) | ConvertTo-Json -Compress } else { "[]" }
'''


def find_browsers_on_disk():
    """Ищем exe по данным внутри файла (компания + браузерные слова)."""
    _, out = run_ps(EXE_PS.replace("__VENDOR__", VENDOR_RE))
    found = []
    for it in as_list(out):
        text = " ".join([it.get("Path") or "", it.get("Product") or "", it.get("Desc") or ""])
        if re.search(BROWSER_RE, text, re.I):
            found.append(it)
    return found


def ifeo_state(name):
    """'none' - ничего нет, 'ours' - блок наш, 'foreign' - чужой отладчик."""
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO + "\\" + name, 0,
                           winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return "none"
    try:
        try:
            winreg.QueryValueEx(k, MARK)
            return "ours"
        except FileNotFoundError:
            pass
        try:
            winreg.QueryValueEx(k, "Debugger")
            return "foreign"
        except FileNotFoundError:
            return "none"
    finally:
        winreg.CloseKey(k)


def block_name(name):
    name = name.lower()
    if name in NEVER_BLOCK:
        return "защищённое имя, пропуск"
    if ifeo_state(name) == "foreign":
        return "там уже чужая настройка, пропуск"
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, IFEO + "\\" + name, 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, BLOCK_CMD)
    winreg.SetValueEx(k, MARK, 0, winreg.REG_DWORD, 1)
    winreg.CloseKey(k)
    return "заблокирован"


def unblock_name(name):
    if ifeo_state(name) != "ours":
        return False
    path = IFEO + "\\" + name
    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                       winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY)
    for v in ("Debugger", MARK):
        try:
            winreg.DeleteValue(k, v)
        except FileNotFoundError:
            pass
    _, nvalues, _ = winreg.QueryInfoKey(k)[0:3]
    winreg.CloseKey(k)
    if nvalues == 0:
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
        except OSError:
            pass
    return True


def blocked_now():
    names = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO, 0,
                              winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return names
    i = 0
    while True:
        try:
            n = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        if ifeo_state(n) == "ours":
            names.append(n)
    winreg.CloseKey(root)
    return names


def cmd_block():
    names = [n.lower() for n in BROWSER_NAMES]
    print("\nИщу браузеры на диске (может занять минуту)...")
    extra = []
    for it in find_browsers_on_disk():
        n = it["Name"].lower()
        print("  найден: %s  (%s)" % (it["Path"], it.get("Company") or "?"))
        if n not in names and n not in NEVER_BLOCK and n not in extra:
            extra.append(n)
    for n in extra:
        if ask("Добавить в блок ещё и '%s'? (д/н): " % n):
            names.append(n)
    st = load_state()
    print()
    for n in names:
        res = block_name(n)
        print("  %-22s %s" % (n, res))
        if res == "заблокирован" and n not in st["blocked"]:
            st["blocked"].append(n)
            log("Браузер заблокирован: " + n)
    save_state(st)
    print("\nГотово. Антивирус может поругаться на такую настройку - это нормально.")


# ----------------------------------------------------------------------------
# ЗАЩИТА ПРОГРАММЫ + СТОРОЖ
# ----------------------------------------------------------------------------
def install_self():
    """Копируем себя в защищённую папку. Возвращаем команду для сторожа."""
    os.makedirs(APP_DIR, exist_ok=True)
    if getattr(sys, "frozen", False):
        src, dst = sys.executable, os.path.join(APP_DIR, "RKNShield.exe")
        cmd = '"%s" --guard' % dst
    else:
        src, dst = os.path.abspath(__file__), os.path.join(APP_DIR, "rknshield.py")
        cmd = '"%s" "%s" --guard' % (sys.executable, dst)
    if os.path.abspath(src).lower() != dst.lower():
        shutil.copy2(src, dst)
    return cmd


def protect_folder():
    # SID вместо имён, чтобы работало и в русской Windows:
    # S-1-5-32-544 = Администраторы, S-1-5-18 = SYSTEM, S-1-5-32-545 = Пользователи
    run(["icacls", APP_DIR, "/inheritance:r",
         "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
         "/grant:r", "*S-1-5-18:(OI)(CI)F",
         "/grant:r", "*S-1-5-32-545:(OI)(CI)RX"])


def cmd_protect():
    cmd = install_self()
    protect_folder()
    code1, _ = run(["schtasks", "/Create", "/TN", TASKS[0], "/TR", cmd, "/SC", "MINUTE",
                    "/MO", "30", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"])
    code2, _ = run(["schtasks", "/Create", "/TN", TASKS[1], "/TR", cmd, "/SC", "ONSTART",
                    "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"])
    st = load_state()
    st["protected"] = True
    st["guard"] = (code1 == 0 and code2 == 0)
    save_state(st)
    log("Защита включена, сторож: %s" % st["guard"])
    print("\nПапка защищена: %s" % APP_DIR)
    print("Обычные программы (браузеры и т.д.) туда писать не могут.")
    print("Сторож: %s" % ("включён, проверка каждые 30 минут" if st["guard"] else "НЕ получилось включить"))


def guard():
    """Тихий режим для сторожа: перепроверить всё и починить."""
    st = load_state()
    for it in scan_certs():
        kill_certs([it], st)
    for n in list(st["blocked"]):
        if ifeo_state(n) == "none":
            block_name(n)
            log("Сторож вернул блок: " + n)


# ----------------------------------------------------------------------------
# ЧТО ЗАБЛОКИРОВАНО / ОТМЕНА
# ----------------------------------------------------------------------------
def cmd_status():
    st = load_state()
    print("\n=== УДАЛЁННЫЕ СЕРТИФИКАТЫ (в чёрном списке) ===")
    if not st["certs"]:
        print("  пусто")
    for t, info in st["certs"].items():
        print("  - %s\n    отпечаток %s, дата %s" % (info["subject"], t, info["when"]))
    print("\n=== ЗАБЛОКИРОВАННЫЕ БРАУЗЕРЫ ===")
    names = blocked_now()
    print("  " + (", ".join(names) if names else "пусто"))
    print("\n=== ЗАЩИТА ===")
    print("  Папка защищена: %s" % ("да" if st["protected"] else "нет"))
    guard_on = run(["schtasks", "/Query", "/TN", TASKS[0]])[0] == 0
    print("  Сторож работает: %s" % ("да" if guard_on else "нет"))
    print("\n=== ПОСЛЕДНИЕ ЗАПИСИ ЖУРНАЛА ===")
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f.readlines()[-10:]:
                print("  " + line.rstrip())
    except Exception:
        print("  пусто")


def undo_cert(thumb, st):
    info = st["certs"][thumb]
    run(["certutil", "-delstore", "Disallowed", thumb])
    run(["certutil", "-user", "-delstore", "Disallowed", thumb])
    for loc, store in info["places"]:
        cmd = ["certutil"] + (["-user"] if loc == "CurrentUser" else []) + \
              ["-addstore", "-f", store, info["backup"]]
        run(cmd)
    del st["certs"][thumb]
    log("ОТМЕНА: сертификат возвращён: " + info["subject"])


def cmd_undo():
    st = load_state()
    items = []
    for t, info in st["certs"].items():
        items.append(("cert", t, "Вернуть сертификат: " + info["subject"]))
    for n in blocked_now():
        items.append(("block", n, "Разблокировать: " + n))
    if st["guard"]:
        items.append(("guard", None, "Выключить сторожа"))
    if st["protected"]:
        items.append(("prot", None, "Снять защиту с папки программы"))
    if not items:
        print("\nОтменять нечего.")
        return
    print()
    for i, (_, _, text) in enumerate(items, 1):
        print("  [%d] %s" % (i, text))
    print("  [0] Назад      [все] Отменить всё")
    ans = input("Что отменить? ").strip().lower()
    if ans in ("0", ""):
        return
    chosen = items if ans == "все" else []
    if not chosen:
        try:
            chosen = [items[int(ans) - 1]]
        except Exception:
            print("Не понял.")
            return
    for kind, key, _ in chosen:
        if kind == "cert":
            undo_cert(key, st)
        elif kind == "block":
            unblock_name(key)
            if key in st["blocked"]:
                st["blocked"].remove(key)
            log("ОТМЕНА: браузер разблокирован: " + key)
        elif kind == "guard":
            for t in TASKS:
                run(["schtasks", "/Delete", "/TN", t, "/F"])
            st["guard"] = False
            log("ОТМЕНА: сторож выключен")
        elif kind == "prot":
            run(["icacls", APP_DIR, "/reset", "/T"])
            st["protected"] = False
            log("ОТМЕНА: защита папки снята")
    save_state(st)
    print("Готово.")


# ----------------------------------------------------------------------------
# ГЛАВНОЕ МЕНЮ
# ----------------------------------------------------------------------------
MENU = """
==============================
         RKNShield
==============================
 1  Найти сертификаты (только показать)
 2  Удалить сертификаты + чёрный список
 3  Заблокировать русские браузеры
 4  Показать, что заблокировано
 5  Включить защиту программы + сторож
 6  ОТМЕНИТЬ действия
 0  Выход
"""


def main():
    if not is_admin():
        elevate()
    if "--guard" in sys.argv:
        guard()
        return
    os.makedirs(APP_DIR, exist_ok=True)
    actions = {"1": cmd_find, "2": cmd_kill, "3": cmd_block,
               "4": cmd_status, "5": cmd_protect, "6": cmd_undo}
    while True:
        print(MENU)
        choice = input("Выбери номер: ").strip()
        if choice == "0":
            break
        fn = actions.get(choice)
        if fn:
            try:
                fn()
            except Exception as e:
                print("Ошибка: %s" % e)
                log("ОШИБКА: %s" % e)
        else:
            print("Нет такого пункта.")


if __name__ == "__main__":
    main()
