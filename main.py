import time
from multiprocessing import get_context
from random import random
import numpy
import numpy as np
from matplotlib import pyplot as plt
import torch
import torch.distributed.launch
import torch.nn as nn
from numpy import zeros
from torch import device
import pandas as pd
import torch.utils.data as data
import torch.optim as optim
import torch.distributed.launch
from openpyxl import Workbook
import random
import numpy as np
from sklearn.metrics import roc_curve, auc
start = time.time()

from datetime import datetime
starttime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#print (starttime)

batch_size = 8

#build the model
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class lstm(nn.Module):
    def __init__(self, character_size, embedding_dim, hidden_size, num_classes, num_layers, bidirectional):
        super(lstm, self).__init__()
        self.character_size = character_size
        self.embedding_dim = embedding_dim
        self.hidden_size = hidden_size
        self.num_classes = num_classes
        self.num_layers = num_layers
        self.bidirectional = bidirectional

        self.embedding = nn.Embedding(self.character_size, embedding_dim)
        self.lstm = nn.LSTM(input_size=self.embedding_dim, hidden_size=self.hidden_size, batch_first=True,
                            num_layers=self.num_layers, bidirectional=self.bidirectional)
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        batch_size, seq_len = x.shape

        h0 = torch.randn(self.num_layers, batch_size, self.hidden_size).to(device)
        c0 = torch.randn(self.num_layers, batch_size, self.hidden_size).to(device)
        x = self.embedding(x)
        out, (_, _) = self.lstm(x, (h0, c0))
        output = self.fc(out[:, -1, :]).squeeze(0)
        return output

preds_all=[]
labels_all=[]
'''
#make onfusion_matrix
def confusion_matrix(preds, labels, conf_matrix):
    preds = torch.argmax(preds, 1)
    global preds_all
    global labels_all
    print("predict_value",preds)
    print("labels", labels)
conf_matrix = torch.zeros(4, 4)
conf_matrix_test=torch.zeros(4, 4)
print("preds_all",preds_all)
print("labels_all",labels_all)
'''

test_indicators={}
def various_indicators(preds, labels):
    indicators = {}
    TP = np.sum(np.logical_and(np.equal(labels, 1), np.equal(preds, 1)))
    print("TP", TP)
    # false positive
    FP = np.sum(np.logical_and(np.equal(labels, 0), np.equal(preds, 1)))
    print("FP", FP)
    # true negative
    TN = np.sum(np.logical_and(np.equal(labels, 1), np.equal(preds, 0)))
    print("TN", TN)
    # false negative
    FN = np.sum(np.logical_and(np.equal(labels, 0), np.equal(preds, 0)))
    print("FN", FN)
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    F1_Score = 2 * precision * recall / (precision + recall)
    print("precision", precision)
    print("recall", recall)
    print("F1_Score", F1_Score)
    # Receiver Operating Characteristic
    # The horizontal axis False Positive Rate   The vertical axis True Positive Rate
    fpr, tpr, thersholds = roc_curve(labels, preds)
    for i, value in enumerate(thersholds):
        print("fpr[i]%f tpr[i]%f value%f" % (fpr[i], tpr[i], value))

    FPR = FP / (TN + FP)
    # TPR = Recall = TP / (TP + FN)
    TPR = TP / (TP + FN)
    indicators["precision"]=precision
    indicators["recall"] = recall
    indicators["F1_Score"] = F1_Score
    indicators["FPR"] = FPR
    indicators["TPR"] = TPR
    indicators["fpr"] = fpr
    indicators["tpr"] = tpr
    return indicators

#instantiated network
model = lstm(character_size=256, embedding_dim=16, hidden_size=16, num_classes=2, num_layers=2,
                     bidirectional=False).to(device)
criterion = nn.CrossEntropyLoss().to(device)
optimizer = optim.Adamax(model.parameters(), lr=0.001)

#model training process：
model.train()
epoch_num=0
x_num=[]
max_num=0
train_loss=[]
Test_loss=[]
train_acc=[]
test_acc=[]
epoch_times = 8

#get data
df = pd.read_csv('E:/dataset/archive/malicious_phish_copy3.csv',encoding='iso-8859-1')
#convert type to id    convert type to 0-1
df['type_id'] = df['type'].factorize()[0]
type_id_df = df[['type', 'type_id']].drop_duplicates().sort_values('type_id').reset_index(drop=True)
type_to_id = dict(type_id_df.values)
id_to_type = dict(type_id_df[['type_id', 'type']].values)

#randomly take data
num=400
data_pre={}
url_benign = []
label_benign = []
label_malicious = []
url_input = []
url_malicious = []

a=random.randint(0,len(df)-300000)
use_reader = df[a:a+100000]

url_pre = list(use_reader['url'])   #url_pre 'url'
labels_pre = list(use_reader['type_id'])  #labels_pre 'type_id'
count = 0

dic = {}
dic_url={}
dic_label = {}
for index in range(len(labels_pre)):

    if labels_pre[index] == 1:
        if len(dic_url) < num*0.55:
            dic[url_pre[index]] = labels_pre[index]
            dic_url[url_pre[index]] = labels_pre[index]
            count = count + 1
        if len(dic_url) ==num*0.45:
            break
count1=0

for index1 in range(len(labels_pre)):
    if labels_pre[index1] != 1:
        if len(dic_label) < num*0.55:
            dic[url_pre[index1]] = labels_pre[index1]
            dic_label[url_pre[index1]] = labels_pre[index1]
            count1 = count1 + 1
        if len(dic_label) ==num*0.45:
            break
url_pre1 = []
labels_pre1 = []

dict_key_ls = list(dic.keys())
random.shuffle(dict_key_ls)
new_dic = {}
for key in dict_key_ls:
    new_dic[key] = dic.get(key)
    if new_dic[key] !=1:
        new_dic[key] = 0

url_pre1 = new_dic.keys()
labels_pre1 = new_dic.values()

#make the length of each url 256, and make up for the lack of it with 0
for i in url_pre1: #It is url_pre before
    if len(i) < 256:
        i += '0' * (256 - len(i))
    if len(i) > 256:
        i = i[0:256]

#convert the character in each url to the corresponding ascii code
def make_data(url, labels):
    inputs = []
    inputs_sub = []
    url_num=0
    for url_sub in url: #url
        url_num=url_num+1
        for item0 in url_sub:   #the characters in each url
            inputs_sub.append(ord(item0))
        inputs.append(inputs_sub)
    targets = []
    for out in labels:
        targets.append(out)
    return inputs, targets   # url type

train_precision_all=[]
train_recall_all=[]
train_F1_Score_all=[]
train_fpr_all=[]
train_tpr_all=[]

test_precision_all=[]
test_recall_all=[]
test_F1_Score_all=[]
test_fpr_all=[]
test_tpr_all=[]

for epoch in range(epoch_times):

    urls_num_for_each_epoch = 0
    url_pre2=list(url_pre1)
    labels_pre2=list(labels_pre1)
    url_pre_for_each_epoch = url_pre2[urls_num_for_each_epoch:urls_num_for_each_epoch+int(num/epoch_times)]
    labels_pre_for_each_epoch = labels_pre2[urls_num_for_each_epoch:urls_num_for_each_epoch+int(num/epoch_times)]
    urls_num_for_each_epoch+=num/epoch_times

    input_batch, target_batch = make_data(url_pre_for_each_epoch, labels_pre_for_each_epoch)
    input_batch, target_batch = torch.FloatTensor(input_batch), torch.FloatTensor(target_batch)
    input_batch.norm(),target_batch.norm() #normalize
    input_batch, target_batch = torch.LongTensor(input_batch.numpy()), torch.LongTensor(target_batch.numpy())

    model.train()

# divide training set, test set
    from sklearn.model_selection import train_test_split
    #x_test train set y_test validation set z_test test set
    x_train,x_test, y_train,y_test = train_test_split(input_batch, target_batch, test_size=0.2, random_state = 0)

    x_train, x_validate,y_train, y_validate = train_test_split(x_train,y_train,test_size=0.2,random_state = 0)

    train_dataset = data.TensorDataset(torch.as_tensor(x_train), torch.as_tensor(y_train))
    validate_dataset = data.TensorDataset(torch.as_tensor(x_validate), torch.as_tensor(y_validate)) #validation set
    test_dataset = data.TensorDataset(torch.as_tensor(x_test), torch.as_tensor(y_test)) #test set
    dataset = data.TensorDataset(input_batch, target_batch)

    #build LSTM

    train_loader = data.DataLoader(
        dataset=train_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=4,               # multiprocess
        pin_memory=True,
        multiprocessing_context=get_context('loky'),
    )
    validate_loader = data.DataLoader(
        dataset=validate_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=4,              # multiprocess
        pin_memory=True,
        multiprocessing_context=get_context('loky'),
    )
    test_loader = data.DataLoader(
        dataset=test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=4,              # multiprocess
        pin_memory=True,
        multiprocessing_context=get_context('loky'),
    )

    correct_train = 0
    epoch_num+=1
    x_num.append(epoch_num)
    print("epoch[",epoch_num,"]")
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print (time)
    #preds_each_round=[]
    #labels_each_round=[]
    #print("preds_each_round1",preds_each_round)
    #print("labels_each_round1",labels_each_round)
    train_indicators={}

    for batch_x, batch_y in train_loader:
        batch_x, batch_y = batch_x.to(device), batch_y.to(device)
        pred1 = model(batch_x)
        pred2 = pred1.max(1, keepdim=True)[1]
        #train_labels=batch_y.max(1, keepdim=True)[1]
        loss = criterion(pred1, batch_y)
        correct_train += pred2.eq(batch_y.view_as(pred2)).sum().item()
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    print('loss =', '{:.6f}'.format(loss))
    train_loss.append(float('{:.6f}'.format(loss)))
    print('accuracy_train: {}/{} ({:.0f}%)\n'.format(correct_train, len(train_loader.dataset),
                                                   100. * correct_train / len(train_loader.dataset)))
    train_acc.append(100. * correct_train / len(train_loader.dataset))

#The validation process
    model.eval()
    correct = 0
        # 0: 'phishing', 1: 'benign'
    with torch.no_grad():
        for data_validate_loader, target in validate_loader:
            data_validate_loader, target = data_validate_loader.to(device), target.to(device)
            output = model(data_validate_loader)
            pred = output.max(1, keepdim=True)[1]
            correct += pred.eq(target.view_as(pred)).sum().item()

        validate_loss = criterion(output, target)
    print('validate_accuracy: {}/{} ({:.0f}%)\n'.format(correct, len(validate_loader.dataset),
                                                    100. * correct / len(validate_loader.dataset)))

    print("validate_loss", '{:.6f}'.format(validate_loss))
    Test_loss.append(float('{:.6f}'.format(validate_loss)))
    test_acc.append(100. * correct / len(validate_loader.dataset))

print("train_acc",train_acc)
print("test_acc",test_acc)

correct1=0
labels_test=[]
preds_values_test=[]
with torch.no_grad():
    for data_test_loader, target1 in test_loader:
        data_test_loader, target1 = data_test_loader.to(device), target1.to(device)
        output1 = model(data_test_loader)
        pred_test = output1.max(1, keepdim=True)[1]
        correct1 += pred_test.eq(target1.view_as(pred_test)).sum().item()

        preds_values_test += pred_test.tolist()  # 预测的值
        labels_test+=target1.tolist()  #标签的值

       #confusion_matrix(output1, target1, conf_matrix_test)
    print("preds_values_test",preds_values_test)
    print("labels_test", labels_test)
    test_indicators=various_indicators(preds_values_test,labels_test)
    #print(conf_matrix)
    test_loss = criterion(output1, target1)
print('test_accuracy: {}/{} ({:.0f}%)\n'.format(correct1, len(test_loader.dataset),
                                                100. * correct1 / len(test_loader.dataset)))

print("test_loss", '{:.6f}'.format(test_loss))

#draw the picture
max_num_loss1=max(train_loss)
max_num_loss2=max(Test_loss)
if max_num_loss1>max_num_loss2 :
    max_num_loss = max_num_loss1
else:
    max_num_loss = max_num_loss2

min_num_loss1=min(train_loss)
min_num_loss2=min(Test_loss)
if min_num_loss1<min_num_loss2 :
    min_num_loss = min_num_loss1
else:
    min_num_loss = min_num_loss2

plt.figure(figsize=(epoch_times,epoch_times))
y_min=min_num_loss-(max_num_loss-min_num_loss)*0.5
y_max=max_num_loss+(max_num_loss-min_num_loss)*0.3
if y_min < 0:
    y_min=0
if y_max > 100:
    y_max = 100
plt.ylim(y_min,y_max)
plt.plot(x_num,train_loss,x_num,Test_loss)
plt.legend(['train','test'], loc='upper right')
plt.xlabel('epoch')
plt.ylabel("loss rate")
plt.savefig('_loss_png')


max_num_acc1=max(train_acc)
max_num_acc2=max(test_acc)
min_num_acc1=min(train_acc)
min_num_acc2=min(test_acc)
plt.figure(figsize=(epoch_times,epoch_times))
if max_num_acc1>max_num_acc2 :
    max_num_acc = max_num_acc1
else:
    max_num_acc = max_num_acc2
if min_num_acc1<min_num_acc2 :
    min_num_acc = min_num_acc1
else:
    min_num_acc = min_num_acc2

y_min1=min_num_loss-(max_num_loss-min_num_loss)*0.5
y_max1=max_num_acc+(max_num_acc*1.2-min_num_acc)*0.5
if y_min1 < 0:
    y_min1=0
if y_max1 > 100:
    y_max1 = 100
plt.ylim(y_min1,y_max1)
plt.plot(x_num,train_acc,x_num,test_acc)
plt.legend(['train','test'], loc='upper right')
plt.xlabel('epoch')
plt.ylabel("accuracy")
plt.savefig('_acc_png')


fpr_get=test_indicators["fpr"]
tpr_get=test_indicators["tpr"]
roc_auc = auc(fpr_get, tpr_get)
plt.figure(figsize=(1.1,1.1))
plt.plot(fpr_get, tpr_get, 'k--', label='ROC (area = {0:.2f})'.format(roc_auc), lw=2)

plt.xlim([-0.05, 1.05])
plt.ylim([-0.05, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc="lower right")
plt.show()
