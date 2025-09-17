import pickle


def main():
    with open("evil.pkl", "rb") as f:
        pickle.load(f)


if __name__ == "__main__":
    main()
