import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import io
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier, plot_tree

st.set_page_config(page_title="Malwhere", layout="wide")
st.title("Malwhere Visual Dashboard")

st.markdown(
    """
    This dashboard inspects provided network traffic logs and classifies them as either 'normal' or 'attack' based on a trained Decision Tree model. The model is trained on the NSL-KDD dataset, which is a widely used benchmark for intrusion detection systems. The dashboard allows users to upload their own network traffic logs in CSV/txt format, visualize the decision tree, and see the classification results.
    """
)

