# privacy.py

class PrivacyManager:
    @staticmethod
    def evaluate_payload(email_data: dict, is_private: bool, model_predict_func):
        """
        Enforces Local Ephemeral Inference.
        If is_private is True, the payload remains strictly in memory
        and is never logged or persisted
        """
        prediction_result = model_predict_func(email_data)

        if not is_private:
            # Telemetry for model retraining is only collected if privacy mode is disabled
            # Database.log_observation(email_data, prediction_result)
            pass

        # email_data falls out of scope here and is garbage-collected
        return prediction_result
