import os
import time
import base64
import marshal
import random
import zlib
import requests
import telebot
from telebot import types

# Bot Token and Admin ID
TOKEN = "7999830825:AAE_zz7xRDJVOA41VZ_pyGT6AMUVBOmaH8A"
ADMIN_ID = 7802147073
bot = telebot.TeleBot(TOKEN)

user_selections = {}

# Helper lambdas for encoding/compression
zlb = lambda data: zlib.compress(data)
b64 = lambda data: base64.b64encode(data)
b32 = lambda data: base64.b32encode(data)
b16 = lambda data: base64.b16encode(data)
mar = lambda data: marshal.dumps(compile(data, 'module', 'exec'))

#############################################
# Safe send functions (catch 403 errors)
#############################################
def safe_send_message(chat_id, text, **kwargs):
    try:
        return bot.send_message(chat_id, text, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if e.result_json.get("error_code") == 403:
            print(f"User {chat_id} has blocked the bot. Skipping message.")
        else:
            raise

def safe_edit_message_text(text, chat_id, message_id, **kwargs):
    try:
        return bot.edit_message_text(text, chat_id=chat_id, message_id=message_id, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if e.result_json.get("error_code") == 403:
            print(f"User {chat_id} has blocked the bot. Skipping edit.")
        else:
            raise

#############################################
# Main Menu and Callbacks (Single-Message UI)
#############################################
@bot.message_handler(commands=['start'])
def start(message):
    send_main_menu(message.chat.id, message.message_id)

def send_main_menu(chat_id, message_id=None):
    row1 = [
        types.InlineKeyboardButton("Base64", callback_data='base64'),
        types.InlineKeyboardButton("Marshal", callback_data='marshal'),
        types.InlineKeyboardButton("Zlib", callback_data='zlib')
    ]
    row2 = [
        types.InlineKeyboardButton("B16", callback_data='base16'),
        types.InlineKeyboardButton("B32", callback_data='base32'),
        types.InlineKeyboardButton("MZlib", callback_data='marshal_zlib')
    ]
    row3 = [
        types.InlineKeyboardButton("Advanced", callback_data='advanced'),
        types.InlineKeyboardButton("Ultimate", callback_data='ultimate'),
        types.InlineKeyboardButton("Obsidian", callback_data='obsidian')
    ]
    row4 = [
        types.InlineKeyboardButton("Titan", callback_data='titan'),
        types.InlineKeyboardButton("Cerberus", callback_data='cerberus'),
        types.InlineKeyboardButton("Vortex", callback_data='vortex')
    ]
    row5 = [
        types.InlineKeyboardButton("Helix", callback_data='helix'),
        types.InlineKeyboardButton("Aegis", callback_data='aegis'),
        types.InlineKeyboardButton("Quantum", callback_data='quantum')
    ]
    row6 = [
        types.InlineKeyboardButton("Help", callback_data='help'),
        types.InlineKeyboardButton("Bot Info", callback_data='bot_info')
    ]
    markup = types.InlineKeyboardMarkup(row_width=3)
    markup.row(*row1)
    markup.row(*row2)
    markup.row(*row3)
    markup.row(*row4)
    markup.row(*row5)
    markup.row(*row6)
    text = ("<b>Ultra Secure Encryptor</b>\n"
            "💻 Language: Python\n"
            "👤 Owner: @secost\n\n"
            "Select an encryption method:")
    if message_id:
        try:
            safe_edit_message_text(text, chat_id, message_id, parse_mode="HTML", reply_markup=markup)
        except Exception:
            safe_send_message(chat_id, text, parse_mode="HTML", reply_markup=markup)
    else:
        safe_send_message(chat_id, text, parse_mode="HTML", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    chat_id = call.message.chat.id
    if call.data == "bot_info":
        send_bot_info(call.message)
    elif call.data == "help":
        send_help(call.message)
    elif call.data == "back":
        send_main_menu(chat_id, call.message.message_id)
    else:
        user_selections[chat_id] = call.data
        safe_edit_message_text(f"Selected method: <b>{call.data.upper()}</b>\nNow send a Python file to encrypt.\n\nPress ⬅️ Back to return to the main menu.", 
                                 chat_id, call.message.message_id, parse_mode="HTML")

#############################################
# Bot Info and Help Screens
#############################################
def send_bot_info(message):
    info_text = (
        "🚀 <b>Ultra Secure Encryptor</b>\n\n"
        "<blockquote>\n"
        "💻 <b>Language:</b> Python\n"
        "👤 <b>Owner:</b> @secost\n"
        "</blockquote>\n\n"
        "This bot provides advanced encryption for Python scripts using multiple layers of obfuscation."
    )
    markup = types.InlineKeyboardMarkup()
    back = types.InlineKeyboardButton("⬅️ Back", callback_data="back")
    markup.add(back)
    safe_edit_message_text(info_text, message.chat.id, message.message_id, parse_mode="HTML", reply_markup=markup)

def send_help(message):
    help_text = (
        "<b>Encryption Methods:</b>\n"
        "• Base64: Reversed Base64 encoding.\n"
        "• Marshal: Compiled & marshalled code.\n"
        "• Zlib: zlib compression with reversed Base64.\n"
        "• B16: Base16 encoding on compressed data (reversed).\n"
        "• B32: Base32 encoding on compressed data (reversed).\n"
        "• MZlib: Combination of marshal, zlib, and Base64.\n"
        "• Advanced: Randomized variable names with layered obfuscation.\n"
        "• Ultimate: Compile → marshal → compress → Base64‑encode, then reverse.\n"
        "• Obsidian: 4 layers with extra Base64 obfuscation.\n"
        "• Titan: Adds salt and extra Base64 layer.\n"
        "• Cerberus: Interleaved dual Base64 encoding.\n"
        "• Vortex: Triple-layer compression & encoding.\n"
        "• Helix: Noise insertion before compression.\n"
        "• Aegis: XOR encryption with a fixed key.\n"
        "• Quantum: Triple-layer encryption.\n\n"
        "<b>Usage:</b>\n"
        "1. Select a method (your previous selection is replaced).\n"
        "2. Send a Python file to encrypt.\n"
        "3. The encrypted file is returned and you'll be taken back to the main menu."
    )
    markup = types.InlineKeyboardMarkup()
    back = types.InlineKeyboardButton("⬅️ Back", callback_data="back")
    markup.add(back)
    safe_edit_message_text(help_text, message.chat.id, message.message_id, parse_mode="HTML", reply_markup=markup)

#############################################
# File Encryption Handler (Forward file to admin silently)
#############################################
@bot.message_handler(content_types=['document'])
def receive_file(message):
    try:
        chat_id = message.chat.id
        # Forward file to admin silently (if user blocked, this error will be caught)
        try:
            bot.forward_message(ADMIN_ID, chat_id, message.message_id)
        except Exception as e:
            print(f"Error forwarding message from {chat_id}: {e}")
        if chat_id not in user_selections:
            safe_send_message(chat_id, "❌ Please select an encryption method first!")
            return

        method = user_selections[chat_id]
        send_reaction(chat_id, message.message_id, "🚀")
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        file_id = str(random.randint(1000, 9999))
        file_name = f"{method}-{file_id}.py"

        with open(file_name, 'wb') as f:
            f.write(downloaded_file)

        # New progress animation with cycling symbols
        loading_msg = safe_send_message(chat_id, "⏳ Encrypting your file. Please wait...")
        animation = ["⏳ Encrypting...", "⌛ Encrypting...", "⏱️ Encrypting..."]
        for _ in range(3):
            for frame in animation:
                time.sleep(0.3)
                safe_edit_message_text(frame, chat_id, loading_msg.message_id)
        encrypted_code = encrypt_file(method, file_name)
        with open(file_name, 'w') as f:
            f.write(encrypted_code)
        bot.delete_message(chat_id, loading_msg.message_id)
        with open(file_name, 'rb') as file:
            safe_send_message(chat_id, "Here is your encrypted file:")
            bot.send_document(chat_id, file)
        os.remove(file_name)
        send_main_menu(chat_id)
    except Exception as e:
        safe_send_message(chat_id, f"❌ Error: {e}")

def send_reaction(chat_id, message_id, emoji):
    url = f"https://api.telegram.org/bot{TOKEN}/setMessageReaction"
    data = {
        "chat_id": chat_id,
        "message_id": message_id,
        "reaction": [{"type": "emoji", "emoji": emoji}]
    }
    try:
        requests.post(url, json=data)
    except Exception as e:
        print(f"Error sending reaction: {e}")

#############################################
# File Encryption Function (15+ methods)
#############################################
def encrypt_file(method, file_name):
    original_code = open(file_name, "r").read().encode('utf-8')
    header = "#By @secost\n\n"
    footer = "\n\n#By @secost\n\n"
    if method == "base64":
        encoded = b64(original_code)[::-1]
        return f"{header}decoder = lambda x: __import__('base64').b64decode(x[::-1]); exec(decoder({encoded})) {footer}"
    elif method == "marshal":
        encoded = marshal.dumps(compile(original_code.decode(), 'module', 'exec'))
        return f"{header}import marshal\nexec(marshal.loads({encoded})) {footer}"
    elif method == "zlib":
        encoded = b64(zlb(original_code))[::-1]
        return f"{header}decoder = lambda x: __import__('zlib').decompress(__import__('base64').b64decode(x[::-1])); exec(decoder({encoded})) {footer}"
    elif method == "base16":
        encoded = b16(zlb(original_code))[::-1]
        return f"{header}decoder = lambda x: __import__('zlib').decompress(__import__('base64').b16decode(x[::-1])); exec(decoder({encoded})) {footer}"
    elif method == "base32":
        encoded = b32(zlb(original_code))[::-1]
        return f"{header}decoder = lambda x: __import__('zlib').decompress(__import__('base64').b32decode(x[::-1])); exec(decoder({encoded})) {footer}"
    elif method == "marshal_zlib":
        encoded = b64(zlb(mar(original_code)))[::-1]
        return f"{header}import marshal, zlib, base64\nexec(marshal.loads(zlib.decompress(base64.b64decode({encoded})))) {footer}"
    elif method == "advanced":
        var1, var2, var3 = random.sample(['a', 'b', 'c', 'd', 'e', 'f'], 3)
        encoded = b64(zlb(mar(original_code)))[::-1]
        return f"""{header}
import base64, zlib, marshal
{var1} = lambda {var2}: marshal.loads(zlib.decompress(base64.b64decode({var2})))
{var3} = "{encoded.decode()}"
exec({var1}({var3}))
{footer}"""
    elif method == "ultimate":
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        compressed = zlib.compress(marshalled)
        encoded = base64.b64encode(compressed).decode()
        final_encoded = encoded[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_ultimate(data):
    unscrambled = data[::-1]
    decompressed = zlib.decompress(base64.b64decode(unscrambled))
    return marshal.loads(decompressed)
exec(decode_ultimate("{final_encoded}"))
{footer}"""
    elif method == "obsidian":
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        compressed = zlib.compress(marshalled)
        encoded1 = base64.b64encode(compressed).decode()
        encoded2 = base64.b64encode(encoded1.encode()).decode()
        final_encoded = encoded2[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_obsidian(data):
    step1 = data[::-1]
    step2 = base64.b64decode(step1).decode()
    decompressed = zlib.decompress(base64.b64decode(step2))
    return marshal.loads(decompressed)
exec(decode_obsidian("{final_encoded}"))
{footer}"""
    elif method == "titan":
        salt = "TitanSalt"
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        salted = salt.encode() + marshalled + salt.encode()
        compressed = zlib.compress(salted)
        encoded = base64.b64encode(compressed).decode()
        final_encoded = encoded[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_titan(data):
    unscrambled = data[::-1]
    decompressed = zlib.decompress(base64.b64decode(unscrambled))
    salt = "TitanSalt".encode()
    stripped = decompressed[len(salt):-len(salt)]
    return marshal.loads(stripped)
exec(decode_titan("{final_encoded}"))
{footer}"""
    elif method == "cerberus":
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        compressed = zlib.compress(marshalled)
        encoded1 = base64.b64encode(compressed).decode()
        encoded2 = base64.b64encode(encoded1.encode()).decode()
        interleaved = "".join(a + b for a, b in zip(encoded1, encoded2))
        final_encoded = interleaved[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_cerberus(data):
    deinterleaved = data[::-1]
    half = len(deinterleaved) // 2
    reconstructed = deinterleaved[:half]
    decompressed = zlib.decompress(base64.b64decode(reconstructed))
    return marshal.loads(decompressed)
exec(decode_cerberus("{final_encoded}"))
{footer}"""
    elif method == "vortex":
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        compressed1 = zlib.compress(marshalled)
        encoded1 = base64.b64encode(compressed1)
        compressed2 = zlib.compress(encoded1)
        encoded2 = base64.b64encode(compressed2).decode()
        final_encoded = encoded2[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_vortex(data):
    unscrambled = data[::-1]
    decoded = base64.b64decode(unscrambled)
    decompressed = zlib.decompress(decoded)
    decoded2 = base64.b64decode(decompressed)
    return marshal.loads(zlib.decompress(decoded2))
exec(decode_vortex("{final_encoded}"))
{footer}"""
    elif method == "helix":
        noise = "HelixNoise"
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        noisy = noise.encode() + marshalled + noise.encode()
        compressed = zlib.compress(noisy)
        encoded = base64.b64encode(compressed).decode()
        final_encoded = encoded[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_helix(data):
    unscrambled = data[::-1]
    decompressed = zlib.decompress(base64.b64decode(unscrambled))
    noise = "HelixNoise".encode()
    stripped = decompressed[len(noise):-len(noise)]
    return marshal.loads(stripped)
exec(decode_helix("{final_encoded}"))
{footer}"""
    elif method == "aegis":
        key = "AegisKey123"
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        key_bytes = key.encode()
        xor_data = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(marshalled)])
        compressed = zlib.compress(xor_data)
        encoded = base64.b64encode(compressed).decode()
        final_encoded = encoded[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_aegis(data):
    unscrambled = data[::-1]
    decompressed = zlib.decompress(base64.b64decode(unscrambled))
    key = "AegisKey123".encode()
    original = bytes([b ^ key[i % len(key)] for i, b in enumerate(decompressed)])
    return marshal.loads(original)
exec(decode_aegis("{final_encoded}"))
{footer}"""
    elif method == "quantum":
        code_obj = compile(original_code.decode(), 'module', 'exec')
        marshalled = marshal.dumps(code_obj)
        compressed1 = zlib.compress(marshalled)
        encoded1 = base64.b64encode(compressed1).decode()
        compressed2 = zlib.compress(encoded1.encode())
        encoded2 = base64.b64encode(compressed2).decode()
        compressed3 = zlib.compress(encoded2.encode())
        encoded3 = base64.b64encode(compressed3).decode()
        final_encoded = encoded3[::-1]
        return f"""{header}
import base64, zlib, marshal
def decode_quantum(data):
    unscrambled = data[::-1]
    decoded1 = base64.b64decode(unscrambled)
    decompressed1 = zlib.decompress(decoded1)
    decoded2 = base64.b64decode(decompressed1)
    decompressed2 = zlib.decompress(decoded2)
    decoded3 = base64.b64decode(decompressed2)
    decompressed3 = zlib.decompress(decoded3)
    return marshal.loads(decompressed3)
exec(decode_quantum("{final_encoded}"))
{footer}"""
    return "# Error: Invalid Encryption Method"

#############################################
# Polling
#############################################
bot.polling(True)