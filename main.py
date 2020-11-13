import os
import glob
import json
import pprint

import numpy as np

from lightgbm import LGBMClassifier

from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import RFE

SEED = 41

def read_label_csv(path):
    label_table = dict()
    with open(path, "r") as f:
        for line in f.readlines()[1:]:
            fname, label = line.strip().split(",")
            label_table[fname] = int(label)
    return label_table

def read_json(path):
    with open(path, "r") as f:
        return json.load(f)

def load_model(**kwargs):
    if kwargs["model"] == "rf":
        return RandomForestClassifier(random_state=kwargs["random_state"], n_jobs=4)
    elif kwargs["model"] == "dt":
        return DecisionTreeClassifier(random_state=kwargs["random_state"])
    elif kwargs["model"] == "lgb":
        return LGBMClassifier(random_state=kwargs["random_state"])
    elif kwargs["model"] == "svm":
        return SVC(random_state=kwargs["random_state"])
    elif kwargs["model"] == "lr":
        return LogisticRegression(random_state=kwargs["random_state"], n_jobs=-1)
    elif kwargs["model"] == "knn":
        return KNeighborsClassifier(n_jobs=-1)
    elif kwargs["model"] == "adaboost":
        return AdaBoostClassifier(random_state=kwargs["random_state"])
    elif kwargs["model"] == "mlp":
        return MLPClassifier(random_state=kwargs["random_state"])
    else:
        print("Unsupported Algorithm")
        return None
    

def train(X_train, y_train, model):
    '''
        머신러닝 모델을 선택하여 학습을 진행하는 함수
	
        :param X_train: 학습할 2차원 리스트 특징벡터
        :param y_train: 학습할 1차원 레이블 벡터
        :param model: 선택할 머신러닝 알고리즘
        :return: 학습된 머신러닝 모델
    '''
    clf = load_model(model=model, random_state=SEED)
    clf.fit(X_train, y_train)
    return clf


def evaluate(X_test, y_test, model):
    '''
        학습된 머신러닝 모델로 검증 데이터를 검증하는 함수
	
        :param X_test: 검증할 2차원 리스트 특징 벡터
        :param y_test: 검증할 1차원 리스트 레이블 벡터
        :param model: 학습된 머신러닝 모델 객체
    '''
    predict = model.predict(X_test)

    #--------------------------------
    correct_sum, fail_sum = 0, 0
    for i in range(predict.size):
        if (predict[i] == y_test[i]):
            correct_sum += 1
        else:
            fail_sum += 1
            print(sha_test[i], ":", y_test[i])

    print(correct_sum, " and ", fail_sum)

    #(정상: 0, 악성: 1)
    #--------------------------------

    print("정확도", model.score(X_test, y_test))


class PeminerParser:
    def __init__(self, path):
        self.report = read_json(path)
        self.vector = []
    
    def process_report(self):
        '''
            전체 데이터 사용        
        '''
        
        self.vector = [value for _, value in sorted(self.report.items(), key=lambda x: x[0])]
        return self.vector
    

class EmberParser:
    '''
        예제에서 사용하지 않은 특징도 사용하여 벡터화 할 것을 권장 ★★★★★
    '''
    def __init__(self, path):
        self.report = read_json(path)
        self.vector = []
    
    def get_histogram_info(self):
        histogram = np.array(self.report["histogram"])
        total = histogram.sum()
        vector = histogram / total
        return vector.tolist()
    
    def get_string_info(self):
        strings = self.report["strings"]

        hist_divisor = float(strings['printables']) if strings['printables'] > 0 else 1.0
        vector = [
            strings['numstrings'], 
            strings['avlength'], 
            strings['printables'],
            strings['entropy'], 
            strings['paths'], 
            strings['urls'],
            strings['registry'], 
            strings['MZ']
        ]
        vector += (np.asarray(strings['printabledist']) / hist_divisor).tolist()
        return vector
    
    def get_general_file_info(self):
        general = self.report["general"]
        vector = [
            general['size'], general['vsize'], general['has_debug'], general['exports'], general['imports'],
            general['has_relocations'], general['has_resources'], general['has_signature'], general['has_tls'],
            general['symbols']
        ]
        return vector

    def get_num_of_bak_sections(self): # 0.9426 -> 0.9432로 증가
        section = self.report["section"]
        sections = section['sections']

        cnt = 0
        for section_1 in sections:
            if(section_1['name'] == ".bak"):
                cnt += 1

        return [cnt]

    def process_report(self):
        vector = []
        vector += self.get_general_file_info()
        vector += self.get_histogram_info()
        vector += self.get_string_info()
        '''
            특징 추가 ★★★★★
        '''
        vector += self.get_num_of_bak_sections()
        return vector
    
class PestudioParser:
    '''
        사용할 특징을 선택하여 벡터화 할 것을 권장 ★★★★★
    '''
    
    def __init__(self, path):
        self.report = read_json(path)
        self.vector = []
    
    def process_report(self):
        pass

def feature_label_extract(directory,filename):
    # ## 레이블 테이블 로드
    label_table = read_label_csv(filename)

    # ## 학습데이터 구성
    # - 특징 벡터 구성은 2차원이 되어야함 e.g.  [vector_1, vector_2, ..., vector_n]
    # - 각 벡터는 1차원 리스트, 벡터 크기는 모두 같아야함

    # 데이터의 특징 벡터 모음 : X
    # 데이터의 레이블 모음 : y
    X, y = [], []
    sha_test = [] # here@@@@@@@@@@@@@@@@@@@@@@@@

    file_list = os.listdir(f"./PEMINER/{directory}")
    sha = []

    for i in file_list:
        sha.append( i.replace(".json","") )

    for fname in sha:
        feature_vector = []
        label = label_table[fname]
        for data in ["PEMINER", "EMBER"]:
            path = f"{data}/{directory}/{fname}.json"
            if data == "PEMINER":
                feature_vector += PeminerParser(path).process_report()
            else:
                feature_vector += EmberParser(path).process_report()
        X.append(feature_vector)
        y.append(label)
        sha_test.append(fname) # here@@@@@@@@@@@@@@@@@@@@@@@@

    return X, y, sha_test


X, y, sha_test = feature_label_extract("학습데이터","학습데이터_정답.csv")

# ## 학습 및 검증
# 학습
models = []
for model in ["rf", "lgb"]:
    clf = train(X, y, model)
    models.append(clf)

#---------------------------------------------------------------

X, y, sha_test = feature_label_extract("검증데이터","검증데이터_정답.csv")

# 검증
# 실제 검증 시에는 제공한 검증데이터를 검증에 사용해야 함
for model in models:
    evaluate(X, y, model)