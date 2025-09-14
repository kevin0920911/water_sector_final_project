# DELAT PCL 攻擊腳本

## 攻擊展示
![攻擊展示影片](https://youtu.be/SEHXqMa8fA4)

## 介紹
這是一個用MITM 攻擊DELAT PLC 的腳本，且這台PLC 已經開啟了modbus 模式，因此可以使用modbus 協定來讀取或寫入PLC 的資料。

## 使用方式
首先先安裝所需的套件
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 執行腳本
```
sudo python DELAT/delat_pcl_attack.py
```

