import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import io
import time
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier, plot_tree

# Page Config
st.set_page_config(page_title="Malwhere - Based on Decision Tree Methodology", layout="wide")

# NSL-KDD Columns
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level"
]

# Identify expected features (excluding labels)
expected_features = [c for c in columns if c not in ['label', 'difficulty_level']]

# 1. Training the Decision Tree Model
@st.cache_resource
def get_trained_pipeline():
    try:
        train_df = pd.read_csv("KDDTrain+.txt", names=columns, header=None)
    except FileNotFoundError:
        st.error("Missing 'KDDTrain+.txt' in this directory. Please add it to train the base model.")
        st.stop()
        
    X_train = train_df[expected_features]
    y_train = train_df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
    
    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    
    nominal_cols = ['protocol_type', 'service', 'flag']
    numeric_cols = [c for c in X_train.columns if c not in nominal_cols]
    
    preprocessor = ColumnTransformer(transformers=[
        ('num', StandardScaler(), numeric_cols),
        ('nom', OneHotEncoder(handle_unknown='ignore'), nominal_cols)
    ])
    
    # Restrict depth so visualization renders clearly
    clf = DecisionTreeClassifier(max_depth=5, random_state=42)
    
    pipeline = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', clf)])
    pipeline.fit(X_train, y_train_enc)
    
    return pipeline, le, preprocessor

pipeline, label_encoder, preprocessor = get_trained_pipeline()

# Sidebar for controls
st.sidebar.title("🌲 Decision Tree Controls")
max_viz_depth = st.sidebar.slider("Visualization Split Depth", min_value=1, max_value=5, value=3)

st.title("Malwhere🔍 - Network Traffic Attack Detector")
st.write("This dashboard inspects provided network traffic logs and classifies them as either 'normal' or 'attack' based on a trained Decision Tree model. The model is trained on the NSL-KDD dataset, which is a widely used benchmark for intrusion detection systems. The dashboard allows users to upload their own network traffic logs in CSV/txt format, visualize the decision tree, and see the classification results.")

st.subheader("Upload Custom Network Logs")
st.write("Upload a CSV or TXT file matching the NSL-KDD format (with or without labels).")
    
uploaded_file = st.file_uploader("Choose a file...", type=["txt", "csv"])
    
if uploaded_file is not None:
    try:
        # Read a small sample to determine column structures safely
        sample = uploaded_file.read(2048).decode('utf-8')
        uploaded_file.seek(0)
            
        first_line = sample.split('\n')[0]
        num_cols = len(first_line.split(','))
            
        # Identify if the file contains text headers or raw numeric rows
        has_header = not first_line.split(',')[0].replace('.', '', 1).isdigit()
            
        if has_header:
            input_df = pd.read_csv(uploaded_file)
        else:
            input_df = pd.read_csv(uploaded_file, names=columns[:num_cols], header=None)
                
        st.success("Data successfully loaded!")
            
        # Enforce alignment with training features
        features_to_predict = input_df.copy()
            
        # Fill in any missing expected columns with 0
        for col in expected_features:
            if col not in features_to_predict.columns:
                features_to_predict[col] = 0
                    
        # Reindex columns so the ordering perfectly mirrors the training dataset
        features_to_predict = features_to_predict[expected_features]

        # Start timer
        start_time = time.perf_counter()
            
        # Generate classification predictions
        predictions_enc = pipeline.predict(features_to_predict)

        # Stop timer
        elapsed_time = time.perf_counter() - start_time
        st.info(f"Classification completed in {elapsed_time:.4f} seconds.")

        predictions = label_encoder.inverse_transform(predictions_enc)
            
        # Map results back to the displayed data frame
        input_df['Predicted_Status'] = predictions
            
        # Summary metrics
        c1, c2 = st.columns(2)
        attack_count = np.sum(predictions == 'attack')
        normal_count = np.sum(predictions == 'normal')
            
        c1.metric("Flagged Attacks 🚨", f"{attack_count:,}")
        c2.metric("Normal Traffic ✅", f"{normal_count:,}")
            
        st.subheader("Processed Outputs")
            
        # Safely display standard tracking columns if they exist
        display_cols = [c for c in ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes'] if c in input_df.columns]
        if 'Predicted_Status' not in display_cols:
            display_cols.append('Predicted_Status')
            
        st.dataframe(input_df[display_cols].head(50))
            
        # Download configuration
        csv_buffer = io.StringIO()
        input_df.to_csv(csv_buffer, index=False)
        st.download_button(
            label="📥 Download Full Assessment Results",
            data=csv_buffer.getvalue(),
            file_name="network_predictions.csv",
            mime="text/csv"
        )
        
        st.markdown("---")
        st.header("📊 Threat Intelligence Dashboard")
        
        # Row 1 and 2: Traffic Breakdown and Protocol Distribution (Side-by-Side)
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("Traffic Composition Split")
            st.write("Proportion of network traffic classified as 'normal' versus 'attack'.")

            # Fixed, compact layout for the donut chart
            fig1, ax1 = plt.subplots(figsize=(5, 4))

            colors = ['#ff4b4b', '#00c853'] if attack_count > 0 else ['#00c853']
            labels = ['Attack', 'Normal'] if attack_count > 0 else ['Normal']
            sizes = [attack_count, normal_count] if attack_count > 0 else [normal_count]
            
            wedges, texts, autotexts = ax1.pie(
                sizes, labels=labels, autopct='%1.1f%%', 
                startangle=90, colors=colors, 
                wedgeprops=dict(width=0.4, edgecolor='w')
            )
            plt.setp(autotexts, size=10, weight="bold")
            plt.tight_layout()
            st.pyplot(fig1)
            plt.close(fig1)

        with chart_col2:
            st.subheader("Threat Vector Distribution by Protocol")
            st.write("Distribution of predicted classifications across different protocol types.")
            
            if 'protocol_type' in input_df.columns:
                proto_df = input_df.groupby(['protocol_type', 'Predicted_Status']).size().unstack(fill_value=0)
                
                # Fixed standard size for the bar chart
                fig2, ax2 = plt.subplots(figsize=(6, 4))
                
                proto_df.plot(kind='bar', stacked=True, color=['#ff4b4b', '#4b94ff'], ax=ax2)
                ax2.set_ylabel("Packet Count")
                ax2.set_xlabel("Protocol Type")
                plt.xticks(rotation=0)
                plt.legend(title="Classification")
                plt.tight_layout()
                st.pyplot(fig2)
                plt.close(fig2)
            else:
                st.info("Protocol distribution unavailable: 'protocol_type' column missing in upload.")

        # Row 3: Feature Importance 
        st.markdown("---")
        st.subheader("Key Predictive Feature Weights")
        st.write("Displays the top 10 features that most influence the Decision Tree's classification decisions.")
        model = pipeline.named_steps['classifier']
        raw_feature_names = pipeline.named_steps['preprocessor'].get_feature_names_out()
        clean_names = [f.replace('num__', '').replace('nom__', '') for f in raw_feature_names]
        
        importances = model.feature_importances_
        feat_imp_df = pd.DataFrame({'Feature': clean_names, 'Importance': importances})
        feat_imp_df = feat_imp_df.sort_values(by='Importance', ascending=True).tail(10)
        
        fig_width = max(15, max_viz_depth * 5)
        fig_height = max(6, max_viz_depth * 2.5)
        fig3, ax3 = plt.subplots(figsize=(fig_width, fig_height))

        ax3.barh(feat_imp_df['Feature'], feat_imp_df['Importance'], color='#333333')
        ax3.set_xlabel("Relative Decision Weight")
        st.pyplot(fig3)
        plt.close(fig3)

        # Row 4: Tree Topology
        st.subheader("Decision Tree Topology Visualization")
        st.write("Displays the rules used by the Decision Tree for classification.")
        
        fig_width = max(15, max_viz_depth * 5)
        fig_height = max(6, max_viz_depth * 2.5)
        fig4, ax4 = plt.subplots(figsize=(fig_width, fig_height))

        plot_tree(
            model, 
            max_depth=max_viz_depth, 
            feature_names=clean_names, 
            class_names=label_encoder.classes_, 
            filled=True, 
            rounded=True, 
            fontsize=7,
            ax=ax4
        )
        plt.tight_layout()
        st.pyplot(fig4)
        plt.close(fig4)
            
    except Exception as e:
        st.error(f"Error parsing file features: {e}. Make sure features align with NSL-KDD formats.")
