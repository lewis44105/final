import face_recognition
import cv2
import numpy as np
from picamera2 import Picamera2
import time
import pickle
import datetime
import os
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from flask import Flask, Response, render_template_string

# --- GPIO & RGB灯配置 ---
import RPi.GPIO as GPIO

LED_R = 17
LED_G = 27
LED_B = 22

GPIO.setmode(GPIO.BCM) # 使用BCM编号
GPIO.setwarnings(False)
GPIO.setup(LED_R, GPIO.OUT)
GPIO.setup(LED_G, GPIO.OUT)
GPIO.setup(LED_B, GPIO.OUT)

# 定义换色函数，每次变色前先熄灭所有灯
def set_led_color(color):
    GPIO.output(LED_R, GPIO.LOW)
    GPIO.output(LED_G, GPIO.LOW)
    GPIO.output(LED_B, GPIO.LOW)
    
    if color == 'red':
        GPIO.output(LED_R, GPIO.HIGH)
    elif color == 'green':
        GPIO.output(LED_G, GPIO.HIGH)
    elif color == 'blue':
        GPIO.output(LED_B, GPIO.HIGH)

set_led_color('red') # 系统刚启动时，默认亮红灯代表上锁状态

os.makedirs("intruders", exist_ok=True)

# 邮箱报警设置
SENDER_EMAIL = "2241885388@qq.com"  
AUTH_CODE = "iwllxnhhgacgdihb"       
RECEIVER_EMAIL = "2241885388@qq.com" 

# 活体检测参数以及缩放比例
EYE_AR_THRESH = 0.22
EYE_AR_CONSEC_FRAMES = 2
cv_scaler = 2

# 全局状态变量
blink_counter = 0
liveness_passed = False
already_logged = False
is_unlocked = False         
unlock_time = 0             
last_capture_time = 0       
global_status_text = "Status:LOCKED"
global_status_color = (0, 0, 255) 

# 身份缓存
current_face_name = None  

# 画面显示控制变量
face_locations = []
face_names = []
frame_count = 0
start_time = time.time()
fps = 0
#全局变量以及锁，这里有一个线程锁，保证一张照片不会在传输到网页的同时在本地被更新，避免撕裂
output_frame = None
frame_lock = threading.Lock()
app = Flask(__name__)

#监控网页 HTML 模板，src指向一个api接口，那么浏览器就会一直更新这张图片
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>网页实时监看</title>
    <style>
        body { text-align: center; background-color: #222; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin-top: 50px; }
        h1 { color: #00ffcc; }
        img { border: 4px solid #444; border-radius: 12px; box-shadow: 0px 0px 20px rgba(0,255,204,0.3); max-width: 90%; height: auto; }
        .footer { margin-top: 30px; font-size: 14px; color: #aaa; }
    </style>
</head>
<body>
    <img src="{{ url_for('video_feed') }}">
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

def generate():
    global output_frame, frame_lock
    while True:
        with frame_lock:#获取锁
            if output_frame is None:
                continue
            (flag, encodedImage) = cv2.imencode(".jpg", output_frame)#压缩jpg
            if not flag:
                continue
        # 将图片打包成连续的 MJPEG 视频流传输，利用yield持续更新，利用更新的图片来实现视频流
        yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + bytearray(encodedImage) + b'\r\n')
@app.route("/video_feed")
def video_feed():#这一段就是返回给flask的，利用generate每次yield的值，使用x-mixed-replace方法每次得到新图片就替换，并设定boundary（分隔符）告诉这个函数如何分割这一个jpg数据包
    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")

print("[INFO] loading encodings...")
with open("encodings.pickle", "rb") as f:
    data = pickle.loads(f.read())
known_face_encodings = data["encodings"]
known_face_names = data["names"]

picam2 = Picamera2()
picam2.configure(picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (640, 480)}))
picam2.start()

# 异步邮件警告
def send_email_async(image_path, timestamp):
    def send():
        try:
            print(f"\n正在将入侵者照片发送至{RECEIVER_EMAIL}")
            msg = MIMEMultipart()
            msg['Subject'] = '检测到陌生人'
            msg['From'] = SENDER_EMAIL
            msg['To'] = RECEIVER_EMAIL
            text = MIMEText(f"警告！系统在 {timestamp} 抓拍到未授权的陌生人，请查看附件", 'plain', 'utf-8')
            msg.attach(text)
            with open(image_path, 'rb') as f:
                img_data = f.read()
            image = MIMEImage(img_data, name=os.path.basename(image_path))
            msg.attach(image)
            server = smtplib.SMTP_SSL("smtp.qq.com", 465)
            server.login(SENDER_EMAIL, AUTH_CODE)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
            server.quit()
            print("警报邮件及照片附件已发送至邮箱\n")
        except Exception as e:
            print(f"\n邮件发送报错: {e}\n")
    threading.Thread(target=send, daemon=True).start()

def log_unlock(name):
    now = datetime.datetime.now()
    dt_string = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("unlock_log.txt", "a") as f:
        f.write(f"{name},{dt_string}\n")
    print(f"[开锁成功] {name} 已记录于 {dt_string}")

def eye_aspect_ratio(eye_points):
    A = np.linalg.norm(np.array(eye_points[1]) - np.array(eye_points[5]))
    B = np.linalg.norm(np.array(eye_points[2]) - np.array(eye_points[4]))
    C = np.linalg.norm(np.array(eye_points[0]) - np.array(eye_points[3]))
    return (A + B) / (2.0 * C)

# 核心处理
def process_frame(frame):
    global face_locations, face_names, blink_counter, liveness_passed, already_logged
    global is_unlocked, unlock_time, last_capture_time
    global global_status_text, global_status_color
    global current_face_name
    
    if is_unlocked and (time.time() - unlock_time > 3):
        print("门已上锁")
        is_unlocked = False
        liveness_passed = False 
        already_logged = False
        current_face_name = None
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255) 
        set_led_color('red')

    if not is_unlocked and global_status_text != "WARNING: INTRUDER":
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255)

    resized_frame = cv2.resize(frame, (0, 0), fx=(1/cv_scaler), fy=(1/cv_scaler))
    rgb_resized_frame = cv2.cvtColor(resized_frame, cv2.COLOR_BGR2RGB)
    
    face_locations = face_recognition.face_locations(rgb_resized_frame)
    face_names = []
    
    if len(face_locations) != 1:
        blink_counter = 0
        current_face_name = None
        if not is_unlocked: 
            liveness_passed = False
            already_logged = False
        if len(face_locations) > 1:
            for _ in face_locations:
                face_names.append("Only 1 face allowed!")
        elif len(face_locations) == 0 and not is_unlocked:
            global_status_text = "Status: LOCKED"
            global_status_color = (0, 0, 255)
            set_led_color('red')
        return frame 
        
    face_location = face_locations[0]
    if current_face_name is None:
        encodings = face_recognition.face_encodings(rgb_resized_frame, [face_location], model='large')
        if len(encodings) > 0:
            face_encoding = encodings[0]
            face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
            if len(face_distances) > 0:
                best_match_index = np.argmin(face_distances)
                STRICT_THRESHOLD = 0.45 
                if face_distances[best_match_index] < STRICT_THRESHOLD:
                    current_face_name = known_face_names[best_match_index]
                else:
                    current_face_name = "Unknown"
            else:
                current_face_name = "Unknown"
        else:
            current_face_name = "Unknown"
        print(f"发现人脸，初步判定为: {current_face_name}")
        
    if current_face_name == "Unknown":
        face_names.append("Unknown")
        global_status_text = "WARNING: INTRUDER!"
        global_status_color = (0, 165, 255) 
        set_led_color('blue')
        
        if time.time() - last_capture_time > 5:
            now = datetime.datetime.now()
            now_str = now.strftime('%Y%m%d_%H%M%S')
            time_formatted = now.strftime('%Y-%m-%d %H:%M:%S')
            filename = f"intruders/intruder_{now_str}.jpg"
            
            cv2.imwrite(filename, frame) 
            print(f"发现陌生人，已抓拍: {filename}")
            send_email_async(filename, time_formatted)
            last_capture_time = time.time()
            
    else:
        face_landmarks_list = face_recognition.face_landmarks(rgb_resized_frame, face_locations)
        if len(face_landmarks_list) > 0:
            face_landmarks = face_landmarks_list[0]
            
            if not liveness_passed:
                if 'left_eye' in face_landmarks and 'right_eye' in face_landmarks:
                    left_ear = eye_aspect_ratio(face_landmarks['left_eye'])
                    right_ear = eye_aspect_ratio(face_landmarks['right_eye'])
                    ear = (left_ear + right_ear) / 2.0
                    if ear < EYE_AR_THRESH:
                        blink_counter += 1
                    else:
                        if blink_counter >= EYE_AR_CONSEC_FRAMES:
                            liveness_passed = True 
                        blink_counter = 0 
                face_names.append("Blink to unlock") 
                
            else:
                face_names.append(current_face_name)
                if not is_unlocked: 
                    is_unlocked = True
                    unlock_time = time.time() 
                    global_status_text = f"Status: UNLOCKED ({current_face_name})"
                    global_status_color = (0, 255, 0) 
                    set_led_color('green')
                    
                if not already_logged:
                    log_unlock(current_face_name)
                    already_logged = True
            
    return frame

def draw_results(frame):
    for (top, right, bottom, left), name in zip(face_locations, face_names):
        top *= cv_scaler
        right *= cv_scaler
        bottom *= cv_scaler
        left *= cv_scaler
        
        if name in ["Blink to unlock", "Only 1 face allowed"]:
            box_color = (0, 0, 255) 
        elif name == "Unknown":
            box_color = (0, 165, 255) 
        else:
            box_color = (0, 255, 0) 

        cv2.rectangle(frame, (left, top), (right, bottom), box_color, 2)
        cv2.rectangle(frame, (left -3, top - 35), (right+3, top), box_color, cv2.FILLED)
        
        font_scale = 0.7 if name == "Only 1 face allowed" else 1.0
        text_color = (255, 255, 255) if name != "Unknown" else (0, 0, 0)
        cv2.putText(frame, name, (left + 6, top - 6), cv2.FONT_HERSHEY_DUPLEX, font_scale, text_color, 2)
    
    cv2.rectangle(frame, (10, 10), (500, 60), (0, 0, 0), cv2.FILLED)
    cv2.rectangle(frame, (10, 10), (500, 60), global_status_color, 2)
    cv2.putText(frame, global_status_text, (20, 45), cv2.FONT_HERSHEY_SIMPLEX, 1.0, global_status_color, 3)

    return frame

def calculate_fps():
    global frame_count, start_time, fps
    frame_count += 1
    elapsed_time = time.time() - start_time
    if elapsed_time > 1:
        fps = frame_count / elapsed_time
        frame_count = 0
        start_time = time.time()
    return fps


print("启动web服务器")#加上host=“0.0.0.0”保证同一网络下的其他设备可以访问
flask_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False))
flask_thread.daemon = True
flask_thread.start()
print("http://172.20.10.2:5000")
# 主循环
while True:
    frame = picam2.capture_array()
    processed_frame = process_frame(frame)
    display_frame = draw_results(processed_frame)
    current_fps = calculate_fps()
    
    cv2.putText(display_frame, f"FPS: {current_fps:.1f}", (display_frame.shape[1] - 160, 45), 
                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    #将处理好的带框画面存入锁中，供网页读取
    with frame_lock:#先获取锁
        output_frame = display_frame.copy()
    cv2.imshow('Face Rec Running', display_frame)
    if cv2.waitKey(1) == ord("q"):
        break
cv2.destroyAllWindows()
picam2.stop()
GPIO.cleanup()
