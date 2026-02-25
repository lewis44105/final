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
os.makedirs("intruders", exist_ok=True)
#邮箱报警设置
SENDER_EMAIL = "2241885388@qq.com"  
AUTH_CODE = "iwllxnhhgacgdihb"       
RECEIVER_EMAIL = "2241885388@qq.com" 
#活体检测参数以及缩放比例
EYE_AR_THRESH = 0.22
EYE_AR_CONSEC_FRAMES = 2
cv_scaler = 4
# 全局状态变量
blink_counter = 0
liveness_passed = False
already_logged = False
is_unlocked = False         
unlock_time = 0             
last_capture_time = 0       
global_status_text = "Status:LOCKED"
global_status_color = (0, 0, 255) 
#身份缓存
current_face_name = None  
#画面显示控制变量
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
picam2 = Picamera2()
picam2.configure(picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (1920, 1080)}))
picam2.start()
#异步邮件警告
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
#核心处理
def process_frame(frame):
    global face_locations, face_names, blink_counter, liveness_passed, already_logged
    global is_unlocked, unlock_time, last_capture_time
    global global_status_text, global_status_color
    global current_face_name #引入全局身份缓存
    if is_unlocked and (time.time() - unlock_time > 3):
        print("门已上锁")
        is_unlocked = False
        liveness_passed = False 
        already_logged = False
        current_face_name = None #关门后清空身份缓存
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255) 

    if not is_unlocked and global_status_text != "WARNING: INTRUDER":
        global_status_text = "Status: LOCKED"
        global_status_color = (0, 0, 255)

    resized_frame = cv2.resize(frame, (0, 0), fx=(1/cv_scaler), fy=(1/cv_scaler))
    rgb_resized_frame = cv2.cvtColor(resized_frame, cv2.COLOR_BGR2RGB)
    
    face_locations = face_recognition.face_locations(rgb_resized_frame)
    face_names = []
    
    #无人或多人时重置
    if len(face_locations) != 1:
        blink_counter = 0
        current_face_name = None #镜头一离开人，立刻清空缓存
        if not is_unlocked: 
            liveness_passed = False
            already_logged = False
        if len(face_locations) > 1:
            for _ in face_locations:
                face_names.append("Only 1 face allowed!")
        elif len(face_locations) == 0 and not is_unlocked:
            global_status_text = "Status: LOCKED"
            global_status_color = (0, 0, 255)
        return frame 
    face_location = face_locations[0]
    if current_face_name is None:
        #先判断能不能取到encodings
        encodings = face_recognition.face_encodings(rgb_resized_frame, [face_location], model='large')
        if len(encodings) > 0:
            face_encoding = encodings[0]
            face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
            if len(face_distances) > 0:
                best_match_index = np.argmin(face_distances)
                STRICT_THRESHOLD = 0.45  #调整阈值，避免相似的可以开锁
                if face_distances[best_match_index] < STRICT_THRESHOLD:
                    current_face_name = known_face_names[best_match_index]
                else:
                    current_face_name = "Unknown"
            else:
                current_face_name = "Unknown"
        else:
            current_face_name = "Unknown"
        print(f"发现人脸，初步判定为: {current_face_name}")
    #根据缓存好的身份进行不同的识别
    if current_face_name == "Unknown":
        #陌生人逻辑：不需要眨眼，立刻报警抓拍
        face_names.append("Unknown")
        global_status_text = "WARNING: INTRUDER!"
        global_status_color = (0, 165, 255) 
        
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
        #已有的数据，需要经过活体检测
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
                # 眨眼通过可以开锁
                face_names.append(current_face_name)
                if not is_unlocked: 
                    is_unlocked = True
                    unlock_time = time.time() 
                    global_status_text = f"Status: UNLOCKED ({current_face_name})"
                    global_status_color = (0, 255, 0) 
                    
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

#主循环
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
