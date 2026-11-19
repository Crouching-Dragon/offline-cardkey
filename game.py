"""示例业务：数字炸弹。

这是一个"被保护的程序"的模板 —— 只有 app.authorize() 返回 ok 才会被调用，
所以这里一行授权判断都不用写。

你以后的真实产品，就是把 run() 换成自己的业务逻辑。
"""
import random


def run(content: str = "") -> None:
    """content 是授权通过后解出来的核心资源明文，这里当彩蛋展示。"""
    print()
    print("=" * 46)
    print("  数字炸弹")
    print("=" * 46)
    print(" 1~100 之间藏着一颗炸弹，猜到它就输了。")
    print(" 每猜一次范围会缩小，撑过 7 次算你赢。")
    print()

    bomb = random.randint(1, 100)
    low, high = 1, 100

    for i in range(1, 8):
        print(f" 第 {i} 次  （{low} ~ {high}）")
        raw = input(" 猜一个数: ").strip()
        if not raw.isdigit():
            print(" 只能输入数字")
            continue

        guess = int(raw)
        if guess < low or guess > high:
            print(" 超出当前范围了")
            continue

        if guess == bomb:
            print(f"\n 砰！炸弹就是 {bomb}，你输了。")
            return

        if guess < bomb:
            low = max(low, guess + 1)
            print(" 安全，炸弹在更大的数")
        else:
            high = min(high, guess - 1)
            print(" 安全，炸弹在更小的数")

    print(f"\n 撑过 7 次，你赢了。炸弹其实在 {bomb}。")

    if content:
        print()
        print("-" * 46)
        print(" 以下是授权通过后解出来的核心资源：")
        print(content)
        print("-" * 46)
