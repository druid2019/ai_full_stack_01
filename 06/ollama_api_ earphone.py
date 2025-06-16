"""
**************************************
*  @Author  ：   Administrator
*  @Time    ：   2025/6/16 11:51
*  @Project :   smemo
*  @FileName:   ollama_api_ earphone.py
**************************************
"""
import requests

# 基础初始化设置
base_url = "http://localhost:21434/api/generate"
headers = {
    "Content-Type": "application/json"
}


def generate_completion(prompt, model="deepseek-r1:8b"):
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(base_url, headers=headers, json=data)
        response.raise_for_status()
        return response.json().get('response', '')
    except Exception as e:
        print(f"API调用失败: {str(e)}")
        return None


# 调用
if __name__ == "__main__":
    prompt = "你是一个资深的小红书爆款文案专家，擅长结合最新潮流和产品卖点，创作引人入胜、高互动、高转化的笔记文案。请为产品小米蓝牙降噪耳机,生成一篇小红书爆款文案。要求:体现科技感，彰显青春活力，包含标题、正文、至少5个相关标签和5个表情符号。请以完整的JSON格式输出，并确保JSON内容用markdown代码块包裹(例如:“json{{...}}”)"
    result = generate_completion(prompt)
    print(result)