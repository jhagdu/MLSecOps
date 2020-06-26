#!/usr/bin/env python
# coding: utf-8

#Importing Some Required Modules
#Basic Modules
import pandas as pd
import numpy as np
from os import system

#Modules for Plotting Graphs
import plotly.graph_objs as go
import plotly.offline as pyo
import plotly.express as px

#Machine Learning Modules
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

#----------------------------------------------------------------

#Loading our Logs Dataset
dataset = pd.read_csv('/root/MLSecOps/logstash/output/web-server-logs.csv', names=['IP','Res','Bt','TS'])
#Dropping Rows having Null Values
dataset = dataset.dropna()
#Feature Selection
dataset = dataset.drop(['Bt','TS'], axis=1)
dataset = dataset.groupby(['IP','Res']).Res.agg('count').to_frame('Count').reset_index()
dataset.insert(0, 'SNo', range(len(dataset)))
train_data = dataset.drop(['IP'], axis=1)

#----------------------------------------------------------------

#Scaling the Data
sc = StandardScaler()
scaled_data = sc.fit_transform(train_data)

#Creating Model
model = KMeans(n_clusters=4)

#Fit and Predict
pred  = model.fit_predict(scaled_data)

#Adding Cluster Labels to dataset
data_with_pred = pd.DataFrame(scaled_data, columns=['IP_Scaled', 'Res_Scaled','Count_Scaled'])
data_with_pred['Cluster'] = pred
final_data = pd.concat([dataset, data_with_pred], axis=1, sort=False)

#----------------------------------------------------------------

#Plotting Scatter Graph Using Plotly
Graph   = px.scatter(final_data, 'Count', 'IP', 'Cluster', hover_data=['Res'], color_continuous_scale='Jet')
layout  = go.Layout(title='No of Requests Per IP', hovermode='closest')
figure  = go.Figure(data=Graph, layout=layout)
graph = pyo.plot(figure, filename='/root/MLSecOps/IPvsCount.html', auto_open=False)

#----------------------------------------------------------------

#Finding which cluster is representing DoS Attacks
cluster_to_block = []
for index, row in final_data.iterrows():
    if final_data['Count'].loc[index] > 200:
          cluster_to_block.append(final_data['Cluster'].loc[index])
cluster_to_block = max(set(cluster_to_block), key = cluster_to_block.count)

#Making List of IPs to be blocked
Block_IP_data = pd.read_csv('/root/MLSecOps/DoS_IP_Data.csv') 
for index_in_data, row_in_data in final_data.iterrows():
    if final_data['Cluster'].loc[index_in_data] == cluster_to_block:
        if final_data['IP'].loc[index_in_data] not in np.array(Block_IP_data['Block_IP']):
                Block_IP_data = Block_IP_data.append({'Block_IP' : final_data['IP'].loc[index_in_data], 
                                                  'Status':'No'},ignore_index=True)              

#----------------------------------------------------------------

#Blocking IPs
for index, row in Block_IP_data.iterrows():
    if Block_IP_data['Status'].loc[index] == 'No':
        system("iptables -A INPUT -s {0} -j DROP".format(Block_IP_data['Block_IP'].loc[index]))
        Block_IP_data['Status'].loc[index] = 'Yes'

Block_IP_data.to_csv('/root/MLSecOps/DoS_IP_Data.csv', index=False)

#----------------------------------------------------------------
