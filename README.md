# Malwhere
This Streamlit dashboard inspects provided network traffic logs and classifies them as either 'normal' or 'attack' based on a trained Decision Tree model.

## How to Use This Tool
### Step 1:
Clone this repository to your own directory of choice. 
### Step 2:
In the terminal of your IDE of choice, cd to the Malwhere directory. Example: `cd C:/Users/User/Documents/Malwhere`
### Step 3:
In the same terminal, run the command `streamlit run Malwhere.py`. The app should launch in your browser at `localhost:8501`
### Step 4:
In the dashboard window, click on the Upload button
<img width="2554" height="1268" alt="image" src="https://github.com/user-attachments/assets/fa651e66-dde0-4e54-b181-08e2d7cb684d" />
### Step 5:
Select the data file that you wish to run through the algorithm (.CSV/.TXT format, up to 200MB).
<img width="2554" height="1267" alt="image" src="https://github.com/user-attachments/assets/665c6c75-d944-4136-a7f9-132c07e97302" />
### Step 6:
Allow the dashboard to process your data file. You can use the Decision Tree Controls in the sidebar to modify the Visualization Split Depth of the Decision Tree Model (1 = First Decision Rule, 5 = Entire Structure of Tree, including ALL Branches and Leaves)

#### Visualization Split Depth 1:
<img width="2557" height="1268" alt="image" src="https://github.com/user-attachments/assets/b9308f56-76fc-4d68-add6-297dbcff0043" />

#### Visualization Split Depth 3:
<img width="2557" height="1268" alt="image" src="https://github.com/user-attachments/assets/5ce65a03-3b5b-4abd-bcf3-d49f31c2925e" />

#### Visualization Split Depth 5:
<img width="2555" height="1268" alt="image" src="https://github.com/user-attachments/assets/6cb6e1a7-5be0-448b-bbf4-ac6f623d02c6" />

### Conclusion:
We hope you enjoy using our tool to classify and visualize your data!
