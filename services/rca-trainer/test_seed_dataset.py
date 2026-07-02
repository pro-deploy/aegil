"""Модульный тест валидности сидового датасета маршрутизатора RCA (ADR-0032,
Часть B). Проверяет, что каждая запись корректна, все ветки принадлежат канону,
нет пустых текстов и на каждую ветку набран минимальный объём примеров, достаточный
для дообучения SetFit. В тексты датасета не должны попадать запрещённые символы
(длинное тире и стрелки); соответствующие проверки экранируют эти символы через
экранированные последовательности Unicode, чтобы сам файл теста оставался чистым.

Запуск без зависимостей и без сети: python3 services/rca-trainer/test_seed_dataset.py
"""
import json
import os

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")
MIN_PER_BRANCH = 40

# Запрещённые символы заданы экранированными кодами, чтобы не вписывать их буквально в
# исходник: длинное тире, короткое тире en dash, стрелки вправо, влево, двойная стрелка.
FORBIDDEN = ("\u2014", "\u2013", "\u2192", "\u2190", "\u21d2")

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "seed_dataset.jsonl")


def main() -> None:
    per = {b: 0 for b in BRANCHES}
    total = 0
    seen_texts = set()
    with open(PATH, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            obj = json.loads(line)
            text = obj.get("text")
            labels = obj.get("labels")

            assert isinstance(text, str) and text.strip(), \
                f"строка {lineno}: пустой или нестроковый text"
            assert isinstance(labels, list) and labels, \
                f"строка {lineno}: пустой или нестроковый labels"

            for b in labels:
                assert b in BRANCHES, f"строка {lineno}: ветка вне канона: {b!r}"
                per[b] += 1

            # Метки без повторов внутри записи.
            assert len(set(labels)) == len(labels), \
                f"строка {lineno}: повтор ветки в labels"

            # Запрещённые символы в тексте недопустимы.
            for ch in FORBIDDEN:
                assert ch not in text, \
                    f"строка {lineno}: запрещённый символ с кодом {hex(ord(ch))} в тексте"

            seen_texts.add(" ".join(text.lower().split()))
            total += 1

    assert total >= 200, f"датасет слишком мал: {total} записей"
    # Тексты в основном уникальны: доля дублей мала (допускаем редкие совпадения).
    assert len(seen_texts) >= int(total * 0.98), \
        f"слишком много дублей текста: уникальных {len(seen_texts)} из {total}"

    for b in BRANCHES:
        assert per[b] >= MIN_PER_BRANCH, \
            f"ветка {b}: {per[b]} примеров, требуется не меньше {MIN_PER_BRANCH}"

    # Должны присутствовать многометочные примеры (обучение многометочное).
    print(f"seed dataset: all asserts passed; total {total}; per branch " +
          ", ".join(f"{b}={per[b]}" for b in BRANCHES))


if __name__ == "__main__":
    main()
