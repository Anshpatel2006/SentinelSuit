import os
from pathlib import Path
from groq import Groq
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent.parent

load_dotenv(dotenv_path=BASE / ".env")

client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

MODEL_NAME = "openai/gpt-oss-20b"


def generate_report(prompt):

    try:

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Senior Cybersecurity SOC Analyst. "
                        "Return only valid JSON without markdown."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=1800,
            response_format={"type": "json_object"}
        )

        return response.choices[0].message.content

    except Exception as error:

        print("Groq API Error :", error)

        return None
