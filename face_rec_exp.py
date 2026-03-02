#这是打印测试数据的代码
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
import csv
import RPi.GPIO as GPIO

# --- GPIO & RGB灯配置 ---
LED_R = 17
LED_G = 27
LED_B = 22
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(LED_R, GPIO.OUT)
GPIO.setup(LED_G, GPIO.OUT)
GPIO.setup(LED_B, GPIO.OUT)

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

set_led_color('red') # 系统启动默认亮红灯

# --- 创建目录与实验数据文件 ---
os.makedirs("intruders", exist_ok=True)
EXPERIMENT_LOG_FILE = "experiment_results.csv"
if not os.path.exists(EXPERIMENT_LOG_FILE):
    with open(EXPERIMENT_LOG_FILE, "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        # 写入表头（新增 All_Distances 列）
        writer.writerow(["Timestamp", "Name", "Face_Distance", "All_Distances", "Encoding_Time_sec", "Liveness_Time_sec", "Total_Time_sec", "Result"])

# --- 邮箱报警设置 ---
SENDER_EMAIL = "2241885388@qq.com"  
AUTH_CODE = "iwllxnhhgacgdihb"       
RECEIVER_EMAIL = "2241885388@qq.com" 

# --- 活体检测参数及缩放比例 ---
EYE_AR_THRESH = 0.22
EYE_AR_CONSEC_FRAMES = 2
cv_scaler = 2  # 配合低分辨率，改为 2 保证识别精度

# --- 全局状态与计时变量 ---
blink_counter = 0
liveness_passed = False
already_logged = False
is_unlocked = False         
unlock_time = 0             
last_capture_time = 0       
global_status_text = "Status:LOCKED"
global_status_color = (0, 0, 255) 

# --- 实验数据专用变量 ---
current_face_name = None  
current_face_distance = 0.0  
current_all_distances = "" # 用于存放所有人的距离文本
current_encoding_time = 0.0
face_first_seen_time = 0.0

# --- 画面显示控制变量 ---
face_locations = []
face_names = []
frame_count = 0
start_time = time.time()
fps = 0

print("[INFO] loading encodings...")
with open("encodings.pickle", "rb") as f:
    data = pickle.loads(f.read())
known_face_encodings = data["encodings"]
known_face_names = data["names"]

# 降低分辨率以大幅提升 VNC 流畅度和识别帧率
picam2 = Picamera2()
picam2.configure(picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (640, 480)}))
picam2.start()

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

def log_experiment_data(name, distance, all_dist_str, encoding_time, liveness_time, total_time, result_status):
    now = datetime.datetime.now()
    dt_string = now.strftime("%Y-%m-%d %H:%M:%S")
    with open(EXPERIMENT_LOG_FILE, "a", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([dt_string, name, f"{distance:.4f}", all_dist_str, f"{encoding_time:.4f}", f"{liveness_time:.4f}", f"{total_time:.4f}", result_status])
    print(f"[实验记录] {name} | 最佳距离:{distance:.4f} | 其他对比:{all_dist_str} | 提取:{encoding_time:.4f}s | 结果:{result_status}")

def eye_aspect_ratio(eye_points):
    A = np.linalg.norm(np.array(eye_points[1]) - np.array(eye_points[5]))
    B = np.linalg.norm(np.array(eye_points[2]) - np.array(eye_points[4]))
    C = np.linalg.norm(np.array(eye_points[0]) - np.array(eye_points[3]))
    return (A + B) / (2.0 * C)

def process_frame(frame):
    global face_locations, face_names, blink_counter, liveness_passed, already_logged
    global is_unlocked, unlock_time, last_capture_time
    global global_status_text, global_status_color
    global current_face_name
    global current_face_distance, current_all_distances, current_encoding_time, face_first_seen_time
    
    if is_unlocked and (time.time() - unlock_time > 3):
        print("门已上锁")
        is_unlocked = False
        liveness_passed = False 
        already_logged = False
        current_face_name = None 
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255) 
        set_led_color('red')

    if not is_unlocked and global_status_text != "WARNING: INTRUDER!":
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255)

    resized_frame = cv2.resize(frame, (0, 0), fx=(1/cv_scaler), fy=(1/cv_scaler))
    rgb_resized_frame = cv2.cvtColor(resized_frame, cv2.COLOR_BGR2RGB)
    
    face_locations = face_recognition.face_locations(rgb_resized_frame)
    face_names = []
    
    # 画面无人或多人时重置状态
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
    
    # 身份识别与特征提取耗时统计
    if current_face_name is None:
        t_start = time.time()
        encodings = face_recognition.face_encodings(rgb_resized_frame, [face_location], model='large')
        t_end = time.time()
        current_encoding_time = t_end - t_start
        
        if len(encodings) > 0:
            face_encoding = encodings[0]
            face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
            if len(face_distances) > 0:
                
                # 计算并记录和数据库里所有人的距离
                dist_dict = {}
                for db_name, dist in zip(known_face_names, face_distances):
                    if db_name not in dist_dict or dist < dist_dict[db_name]:
                        dist_dict[db_name] = dist
                
                dist_str_list = [f"{k}:{v:.4f}" for k, v in dist_dict.items()]
                current_all_distances = " | ".join(dist_str_list)

                best_match_index = np.argmin(face_distances)
                STRICT_THRESHOLD = 0.45  
                current_face_distance = face_distances[best_match_index]
                
                if current_face_distance < STRICT_THRESHOLD:
                    current_face_name = known_face_names[best_match_index]
                    face_first_seen_time = time.time()
                else:
                    current_face_name = "Unknown"
            else:
                current_face_name = "Unknown"
                current_face_distance = 1.0
                current_all_distances = "None"
        else:
            current_face_name = "Unknown"
            current_face_distance = 1.0
            current_all_distances = "None"
            
        print(f"检测到人脸，初步判定: {current_face_name}，最佳距离: {current_face_distance:.4f}，耗时: {current_encoding_time:.4f}秒")
        
    # 根据身份执行不同逻辑
    if current_face_name == "Unknown":
        face_names.append("Unknown")
        global_status_text = "WARNING: INTRUDER!"
        global_status_color = (0, 165, 255) 
        set_led_color('blue') 
        
        # 记录拦截数据
        if not already_logged:
            log_experiment_data("Unknown", current_face_distance, current_all_distances, current_encoding_time, 0.0, current_encoding_time, "Rejected: Intruder")
            already_logged = True
        
        # 邮件抓拍逻辑
        if time.time() - last_capture_time > 5:
            now = datetime.datetime.now()
            now_str = now.strftime('%Y%m%d_%H%M%S')
            time_formatted = now.strftime('%Y-%m-%d %H:%M:%S')
            filename = f"intruders/intruder_{now_str}.jpg"
            
            cv2.imwrite(filename, cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)) 
            print(f"发现陌生人，已抓拍: {filename}")
            send_email_async(filename, time_formatted)
            last_capture_time = time.time()
            
    else:
        # 已有数据，进行活体检测
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
                # 活体检测通过，执行开锁
                face_names.append(current_face_name)
                if not is_unlocked: 
                    is_unlocked = True
                    unlock_time = time.time() 
                    global_status_text = f"Status: UNLOCKED ({current_face_name})"
                    global_status_color = (0, 255, 0) 
                    set_led_color('green') 
                    
                if not already_logged:
                    liveness_time = time.time() - face_first_seen_time
                    total_time = current_encoding_time + liveness_time
                    # 记录开锁数据
                    log_experiment_data(current_face_name, current_face_distance, current_all_distances, current_encoding_time, liveness_time, total_time, "Success: Unlocked")
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

# --- 主循环 ---
while True:
    frame = picam2.capture_array()
    processed_frame = process_frame(frame)
    display_frame = draw_results(processed_frame)
    current_fps = calculate_fps()
    
    cv2.putText(display_frame, f"FPS: {current_fps:.1f}", (display_frame.shape[1] - 160, 45), 
                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    
    cv2.imshow('Face Rec Running', display_frame)
    
    if cv2.waitKey(1) == ord("q"):
        break

cv2.destroyAllWindows()
picam2.stop()
GPIO.cleanup() # 退出时安全释放GPIO资源
