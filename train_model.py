import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import warnings
warnings.filterwarnings('ignore')

def train_phishing_model():
    """Train model on actual phishing dataset"""
    print(" Training Phishing Detection Model...")
    
    try:
        # Step 1: Load your actual phishing dataset
        print(" Loading phishing.csv dataset...")
        data = pd.read_csv("phishing.csv")
        
        print(f"Dataset loaded: {data.shape[0]} samples, {data.shape[1]} features")
        
        # Step 2: Prepare features and target
        # Drop Index column and use 'class' as target
        X = data.drop(columns=['Index', 'class'])  # Features
        y = data['class']  # Target (-1 = legitimate, 1 = phishing)
        
        print(f"Features shape: {X.shape}")
        print(f"Target distribution:")
        print(y.value_counts())
        
        # Step 3: Split data into training and testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training samples: {X_train.shape[0]}")
        print(f"Testing samples: {X_test.shape[0]}")
        
        # Step 4: Train Multiple Models (Try different algorithms)
        models = {
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=3,
                random_state=42
            ),
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'  # Important for imbalanced data
            )
        }
        
        best_model = None
        best_score = 0
        best_name = ""
        
        for name, model in models.items():
            print(f"\n Training {name}...")
            
            # Train the model
            model.fit(X_train, y_train)
            
            # Predict on test set
            y_pred = model.predict(X_test)
            
            # Calculate accuracy
            accuracy = accuracy_score(y_test, y_pred)
            
            # Cross-validation score
            cv_scores = cross_val_score(model, X, y, cv=5)
            cv_mean = cv_scores.mean()
            
            print(f" {name} Accuracy: {accuracy:.4f}")
            print(f" {name} Cross-Val Score: {cv_mean:.4f}")
            
            # Detailed performance report
            print(f"\n {name} Classification Report:")
            print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
            
            # Confusion matrix (important for phishing detection)
            cm = confusion_matrix(y_test, y_pred)
            print(f" Confusion Matrix:")
            print(f"   Legitimate | Phishing")
            print(f"Legitimate: {cm[0,0]} (TN) | {cm[0,1]} (FP)")
            print(f"Phishing:    {cm[1,0]} (FN) | {cm[1,1]} (TP)")
            
            # Calculate false negatives (MOST IMPORTANT - fake links missed)
            false_negatives = cm[1, 0]
            false_negative_rate = false_negatives / cm[1].sum()
            print(f" False Negatives (Fake links missed): {false_negatives} ({false_negative_rate*100:.2f}%)")
            
            # Select best model based on accuracy and low false negatives
            if accuracy > best_score and false_negative_rate < 0.2:
                best_score = accuracy
                best_model = model
                best_name = name
        
        # Step 5: If no model met criteria, use GradientBoosting as default
        if best_model is None:
            print("\n No model met criteria, using GradientBoosting as default")
            best_model = models['GradientBoosting']
            best_name = 'GradientBoosting'
        
        # Step 6: Final evaluation of best model
        print(f"\n BEST MODEL SELECTED: {best_name}")
        
        # Final predictions with best model
        y_pred_final = best_model.predict(X_test)
        final_accuracy = accuracy_score(y_test, y_pred_final)
        
        print(f" Final Model Accuracy: {final_accuracy:.4f}")
        
        # Feature importance analysis
        if hasattr(best_model, 'feature_importances_'):
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': best_model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print(f"\n Top 10 Most Important Features:")
            print(feature_importance.head(10))
        
        # Step 7: Save the trained model
        with open("model.pkl", "wb") as f:
            pickle.dump(best_model, f)
        
        print(f"\n Model saved as 'model.pkl'")
        print(" Training completed successfully!")
        
        return best_model, final_accuracy
        
    except FileNotFoundError:
        print(" ERROR: 'phishing.csv' file not found!")
        print("Please make sure 'phishing.csv' is in the same directory")
        return None, 0
    except Exception as e:
        print(f" ERROR during training: {e}")
        return None, 0

def create_backup_model():
    """Create a simple model if main training fails"""
    print("\n Creating backup model...")
    
    # Simple model based on common phishing patterns
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.datasets import make_classification
    
    # Create synthetic data that mimics phishing patterns
    X, y = make_classification(
        n_samples=1000, 
        n_features=30, 
        n_informative=15,  # 15 meaningful features
        n_redundant=10,    # 10 redundant features
        n_repeated=5,      # 5 repeated features
        random_state=42
    )
    
    # Adjust y to match our class labels (-1, 1)
    y = np.where(y == 0, -1, 1)
    
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    with open("model_backup.pkl", "wb") as f:
        pickle.dump(model, f)
    
    print(" Backup model saved as 'model_backup.pkl'")
    return model

if __name__ == "__main__":
    print("=" * 60)
    print("           PHISHING DETECTION MODEL TRAINING")
    print("=" * 60)
    
    # Try to train with actual data
    model, accuracy = train_phishing_model()
    
    if model is None:
        print("\n Main training failed, creating backup model...")
        model = create_backup_model()
        print(" Backup model created. Please check if 'phishing.csv' exists.")
    else:
        print(f"\n Training successful! Model accuracy: {accuracy:.4f}")
    
    print("\n Next steps:")
    print("1. Run your Flask app: python app.py")
    print("2. Test with known phishing URLs")
    print("3. Monitor false negative rate")