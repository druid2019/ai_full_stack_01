"""
**************************************
*  @Author  ：   Administrator
*  @Time    ：   2025/6/16 11:25
*  @Project :   smemo
*  @FileName:   ollama_api_coffee.py
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
    prompt = "你是一个资深的小红书爆款文案专家，擅长结合最新潮流和产品卖点，创作引人入胜、高互动、高转化的笔记文案。你的任务是生成环保咖啡杯的小红书文案"
    result = generate_completion(prompt)
    print(result)

