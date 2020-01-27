import logging
import os
import pickle
import sys

import numpy as np
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
<<<<<<< HEAD
import arff
=======
>>>>>>> parallel_sessionizer

from networkml.parsers.pcap.featurizer import extract_features
from networkml.parsers.pcap.reader import parallel_sessionizer
from networkml.utils.training_utils import read_data
from networkml.utils.training_utils import select_features


logging.basicConfig(level=logging.INFO)


class Model:
    def __init__(self, duration, hidden_size=None, labels=None, model=None, model_type=None, threshold_time=None):
        '''
        Initializes functions shared in various models.

        Args:
            duration: Time duration to aggregate features for
        '''

        self.duration = duration
        self.hidden_size = hidden_size
        self.means = None
        self.stds = None
        self.feature_list = None
        self.model = model
        self.model_type = model_type
        self.labels = labels
        self.threshold_time = threshold_time
        self.sessions = None
        self.pcap_file_sessions = {}
        self.logger = logging.getLogger(__name__)
        try:
            if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
                self.logger.setLevel(os.environ['LOG_LEVEL'])
        except Exception as e:  # pragma: no cover
            self.logger.error(
                'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))

    def _augment_data(self, X, y):
        '''
        Augments the data with randomly permuted samples. Added samples are
        labeled Unknown.

        Args:
            X: Numpy 2D array containing data to augment
            y: Numpy 1D array of labels to augment

        Returns:
            X_aug: Numpy 2D array containing augmented data
            y_aug: Numpy 1D array containing labels of augmented data
        '''

        # Randomly permute the inputs, and label the permutations Unknown
        X_permed = np.copy(X)
        for i in range(X_permed.shape[1]):
            np.random.shuffle(X_permed[:, i])

        y_permed = [self.labels.index('Unknown')]*X_permed.shape[0]
        y_permed = np.stack(y_permed)

        X_aug = np.concatenate((X, X_permed), axis=0)
        y_aug = np.concatenate((y, y_permed), axis=0)

        return X_aug, y_aug

    def get_features(self, filepath, source_ip=None):
        '''
        Reads a pcap specified by the file path and returns an array of the
        computed model inputs

        Args:
            filepath: Path to pcap to compute features for

        Returns:
            features: Numpy 2D array containing features for each time bin
            timestamp: datetime of the last observed packet
        '''

        # Read the capture into a feature array
        X = []
        timestamps = []
        if filepath not in self.pcap_file_sessions:
            self.sessionize_pcaps([filepath])
<<<<<<< HEAD
        binned_sessions,lpi_sessions = self.pcap_file_sessions.get(filepath, {})
=======
        binned_sessions = self.pcap_file_sessions.get(filepath, {})
>>>>>>> parallel_sessionizer
        self.sessions = binned_sessions

        if len(binned_sessions) is 0:
            return None, None, None, None, None

<<<<<<< HEAD
        for session_dict,lpi_data in zip(binned_sessions,lpi_sessions):
            if session_dict is not None and len(session_dict) > 0:
                if source_ip is None:
                    feature_list, source_ip, other_ips, capture_source_ip = extract_features(
                        session_dict,lpi_data
                    )
                else:
                    feature_list, _, other_ips, capture_source_ip = extract_features(
                        session_dict,lpi_data,
=======
        for session_dict in binned_sessions:
            if session_dict is not None and len(session_dict) > 0:
                if source_ip is None:
                    feature_list, source_ip, other_ips, capture_source_ip = extract_features(
                        session_dict
                    )
                else:
                    feature_list, _, other_ips, capture_source_ip = extract_features(
                        session_dict,
>>>>>>> parallel_sessionizer
                        capture_source=source_ip
                    )
                X.append(feature_list)
                last_packet = list(session_dict.items())[-1]
                timestamps.append(last_packet[1][0][0])

        if len(X) == 0:
            return None, None, None, None, None

        full_features = np.stack(X)

        # Mean normalize the features
<<<<<<< HEAD
#        try:
#            full_features -= np.expand_dims(self.means, 0)
#            full_features /= np.expand_dims(self.stds, 0)
#            features = full_features[:, self.feature_list]
#        except Exception as e:  # pragma: no cover
#            self.logger.error('Failed because: {0}'.format(str(e)))
#            sys.exit(1)
        return full_features[:,self.feature_list], source_ip, timestamps, other_ips, capture_source_ip


    def arff_unmake(self,arff_object):
        
        X_all, y_all,attributes= [], [], []
        for datum,attribute in zip(arff_object['data'],arff_object['attributes']):
           X_all.append(datum[0:-1])
           y_all.append(int(datum[-1]))
           if not attribute[0]=='class':
            attributes.append(int(attribute[0]))
        return X_all,y_all,attributes

    def arff_make(self,X,y,labels):
        
        X_labelled = [data+[labels[label]] for label,data in zip(y.tolist(),X.tolist())]
        attribs = [(str(attrib),'REAL') for attrib in range(len(X_labelled[0])-1)]
        attribs.append(('class',labels))
        arff_struct = {'relation':'networkml','attributes':attribs,'data':X_labelled}
#        print(X_labelled)
        return arff_struct

=======
        try:
            full_features -= np.expand_dims(self.means, 0)
            full_features /= np.expand_dims(self.stds, 0)
            features = full_features[:, self.feature_list]
        except Exception as e:  # pragma: no cover
            self.logger.error('Failed because: {0}'.format(str(e)))
            sys.exit(1)
        return features, source_ip, timestamps, other_ips, capture_source_ip
>>>>>>> parallel_sessionizer

    def train(self, data_dir):
        '''
        Trains a single layer model on the data contained in the specified
        directory.  Labels found in the directory are augmented with an
        unknown label.

        Args:
            data_dir: Directory containing the training data
        '''

        self.logger.info('Reading data')
<<<<<<< HEAD
#        self.feature_list =[4807,4801,4788,4800,4802,4799,4803,4804,4789,4790,4791,4792,4797,4796,4795,4794,4793,4808,4798,4805,4806,4668,4667,4677,4665,4666,4664,4678,4663,4662,4669,4670,4671,4680,4676,4682,4681,4679,4672,4673,4674,4675,4098,4097,4381,1077,1147,4640,4637,4101,4096,1159,3207,1162,138,4821,4820,4817,4818,4823,4819,4815,4814,4810,4809,4811,4813,4812,4822,4816,4824,4825,4828,4827,4826,4829,3517,1413,4877,4891,4879,4876,4875,4874,4873,4872,4878,4881,4880,4884,4883,4882,4885,4886,4887,4890,4889,4892,4888,4838,4839,4843,4833,4844,4832,4837,4842,4841,4840,4830,4845,4846,4847,4835,4836,4848,4834,4850,4831,4849,4128,4436,4857,4858,4869,4870,4871,4851,4868,4867,4853,4866,4864,4863,4852,4855,4854,4862,4861,4859,4860,4865,4856,1467,123,1469,4127,4113,4102,4763,4762,4756,4755,4766,4764,4758,4759,4760,4761,4754,4753,4752,4747,4765,4746,4748,4751,4749,4750,4757,4745,4734,4732,4733,4725,4731,4730,4729,4728,4727,4735,4736,4737,4742,4744,4743,4741,4726,4738,4739,4740,4724,4722,4720,4723,4721,4707,4712,4713,4710,4711,4709,4715,4705,4704,4708,4714,4716,4706,4719,4718,4717,4464,3160,4103,4398,3072,2048,4695,4696,4703,4691,4689,4690,4692,4687,4693,4694,4702,4688,4697,4700,4701,4685,4699,4686,4698,4684,4683,3195,2171,1024,0,3125,3461,3515,4383,1112,3094,4099,4385,2491,4414,389,4395,3211,4639,1161,137,3708,4100,1104,1538,4104,4422,445,443,2437,4165,3152,1049,4435,4116,1046,4465,4508,4638,4386,4384,1216,4118,1135,2115,3140,1091,68,4141,4167,4496,2070,135,4228,4234,1185,4481,3194,88,2101,2128,4440,4424,1970,3536,53,1926,4393,4548,2950,4568,4112,1705,1163,1655,678,4345,1146,782,1020,1572,912,894,4507,4560,1013]
#        X_all =  np.loadtxt('X_train.csv',delimiter=",")
#        y_all = np.loadtxt('y_train.csv',delimiter=',')
#        new_labels = np.loadtxt('labels.csv',delimiter=',')
#        new_labels = new_labels.tolist()
#        X_test_select = np.loadtxt('X_test_select.csv', delimiter=",")
#        y_train = np.loadtxt('y_train.csv', delimiter=",")
#        y_test = np.loadtxt('y_text.csv', delimiter=",")
#        print(X_normed_select)

#        train_arff = self.arff_make(X_normed_select,y_train)
#        test_arff = self.arff_make(X_test_select,y_test)
#        train_file = open('train.arff','w')
#        test_file = open('test.arff','w')
#        arff.dump(train_arff,train_file)
#        arff.dump(test_arff,test_file)
#        sys.exit(1)


        # First read the data directory for the features and labels

         
=======
        # First read the data directory for the features and labels
>>>>>>> parallel_sessionizer
        X_all, y_all, new_labels = read_data(
            data_dir,
            duration=self.duration,
            labels=self.labels
        )
        self.labels = new_labels
<<<<<<< HEAD
        

        self.logger.info('Making data splits')
        # Split the data into training, validation, and testing sets
#        X_train, X_test, y_train, y_test = train_test_split(
#            X_all,
#            y_all,
#            test_size=0.2,
#            random_state=0
#        )

#        with open('labels.pkl','rb') as fp:
#          self.labels=pickle.load(fp)

#        np.savetxt('X_all.csv',X_all, delimiter=",")
#        np.savetxt('X_test.csv',X_test_select, delimiter=",")
#        np.savetxt('y_all.csv',y_all, delimiter=",")
#        np.savetxt('y_text.csv',y_test, delimiter=",")
#        with open('labels.pkl','rb') as fp:
#            self.labels=pickle.load(fp)
#        all_file = open('all_train_325.arff')
#        all_arff= arff.load(all_file)
#        all_file.close()
#        _,_,self.feature_list=self.arff_unmake(all_arff)
#
#        X_all,y_all = np.loadtxt('X_all.csv',delimiter=',')[:,self.feature_list],np.loadtxt('y_all.csv',delimiter=',')
        
        all_arff = self.arff_make(X_all,y_all,new_labels)
#        test_arff = self.arff_make(X_test_select,y_test)
        all_file = open('all_mega_flow_index.arff','w')
#        test_file = open('test.arff','w')
        arff.dump(all_arff,all_file)
        all_file.close()
#        arff.dump(test_arff,test_file)
        sys.exit(1)



        self.logger.info('Normalizing features')
        # Mean normalize the features, saving the means and variances
#        self.means = X_all.mean(axis=0)
#        self.stds = X_all.std(axis=0)
        # Set the zero standard deviations to 1
#        zero_stds = self.stds <= 1
#        self.stds[zero_stds] = 1
        # Apply the mean normalization transformation to the training dataj
#        X_normed = X_all - np.expand_dims(self.means, 0)
#        X_normed /= np.expand_dims(self.stds, 0)

        
        self.logger.info('Doing feature selection')
        # Select the relevant features from the training set
#        self.feature_list = select_features(X_normed, y_train)
        self.logger.info(self.feature_list)


 #       X_normed_select = X_normed[:,self.feature_list]
#        X_test_select = X_test[:,self.feature_list]

 #       np.savetxt('X_normed_select.csv',X_normed_select, delimiter=",")
 #       np.savetxt('X_test_select.csv',X_test_select, delimiter=",")
 #       np.savetxt('y_train.csv',y_train, delimiter=",")
 #       np.savetxt('y_text.csv',y_test, delimiter=",")

 #       sys.exit(1)

=======

        self.logger.info('Making data splits')
        # Split the data into training, validation, and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X_all,
            y_all,
            test_size=0.2,
            random_state=0
        )

        self.logger.info('Normalizing features')
        # Mean normalize the features, saving the means and variances
        self.means = X_train.mean(axis=0)
        self.stds = X_train.std(axis=0)
        # Set the zero standard deviations to 1
        zero_stds = self.stds <= 1
        self.stds[zero_stds] = 1
        # Apply the mean normalization transformation to the training dataj
        X_normed = X_train - np.expand_dims(self.means, 0)
        X_normed /= np.expand_dims(self.stds, 0)

        self.logger.info('Doing feature selection')
        # Select the relevant features from the training set
        self.feature_list = select_features(X_normed, y_train)
        self.logger.info(self.feature_list)

>>>>>>> parallel_sessionizer
        # If hidden size wasn't specified, default to the mean of the number
        # of features and the size of the label space
        if self.hidden_size is None:
            self.hidden_size = int(1/2*(
                len(self.labels) +
                len(self.feature_list)
            )
            )

        # Augment the data with randomly permuted samples
<<<<<<< HEAD
#        X_aug, y_aug = self._augment_data(X_normed, y_all)

        # Fit the one layer model to the augmented training data
#        X_input = X_aug[:, self.feature_list]

        try:
            self.model.fit(X_all, y_all)
=======
        X_aug, y_aug = self._augment_data(X_normed, y_train)

        # Fit the one layer model to the augmented training data
        X_input = X_aug[:, self.feature_list]

        try:
            self.model.fit(X_input, y_aug)
>>>>>>> parallel_sessionizer
        except Exception as e:  # pragma: no cover
            self.logger.error('Failed because: {0}'.format(str(e)))
            sys.exit(1)

        # Evaulate the model on the augmented test data
<<<<<<< HEAD
 #       X_test_input = X_test - np.expand_dims(self.means, 0)
 #       X_test_input /= np.expand_dims(self.stds, 0)
 #       X_test_aug, y_test_aug = self._augment_data(X_test_input, y_test)
 #       predictions = self.model.predict(X_test_aug[:, self.feature_list])
 #       self.logger.info('F1 score:')
 #       self.logger.info(f1_score(y_test_aug, predictions, average='weighted'))
=======
        X_test_input = X_test - np.expand_dims(self.means, 0)
        X_test_input /= np.expand_dims(self.stds, 0)
        X_test_aug, y_test_aug = self._augment_data(X_test_input, y_test)
        predictions = self.model.predict(X_test_aug[:, self.feature_list])
        self.logger.info('F1 score:')
        self.logger.info(f1_score(y_test_aug, predictions, average='weighted'))
>>>>>>> parallel_sessionizer

    def predict(self, filepath, source_ip=None):
        '''
        Read a capture file from the specified path and make a prediction
        of the source.

        Args:
            filepath: Path of capture file to read

        Returns:
            prediction: list of tuples formatted as (source, probability)
        '''

        features, _, _, _, _ = self.get_features(filepath, source_ip=source_ip)

        if features is None:
            return None
        predictions = self.model.predict_proba(features)
        mean_predictions = np.mean(predictions, axis=0)

        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(mean_predictions)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)
        return prediction

    def sessionize_pcaps(self, pcap_files):
        self.pcap_file_sessions.update(parallel_sessionizer(
            pcap_files, duration=self.duration, threshold_time=self.threshold_time))

<<<<<<< HEAD
    def get_representation(self, filepath, mean=False, source_ip=None):
=======
    def get_representation(self, filepath, mean=True, source_ip=None):
>>>>>>> parallel_sessionizer
        '''
        Computes the mean hidden representation of the input file.

        Args:
            filepath: Path of capture file to represent
            mean: If true(default), averages all the representations into one

        Returns:
            representation:  representation vector of the input file
        '''

        features, source_ip, timestamp, other_ips, capture_ip_source = self.get_features(
            filepath,
            source_ip=source_ip,
        )
        if features is None:
            return None, None, None, None, None, None

        probabilities = []
        representation = features
        if self.model_type == 'randomforest':
            mean_rep = np.mean(representation, axis=0)
            probabilities = self.model.predict_proba(mean_rep.reshape(1, -1))
            probabilities = probabilities[0]
        elif self.model_type == 'onelayer':
            L1_weights = self.model.coefs_[0]
            L1_biases = self.model.intercepts_[0]
            representation = np.maximum(
                np.matmul(features, L1_weights)+L1_biases,
                0
            )

            mean_rep = np.mean(representation, axis=0)

            L2_weights = self.model.coefs_[1]
            L2_biases = self.model.intercepts_[1]
            probabilities = np.matmul(representation, L2_weights) + L2_biases
            probabilities = np.exp(probabilities)
            probabilities /= np.expand_dims(
                np.sum(probabilities, axis=1), axis=1)
            probabilities = np.mean(probabilities, axis=0)

        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(probabilities)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)

        if mean:
            representation = mean_rep
            timestamp = timestamp[-1]

        return representation, source_ip, timestamp, prediction, other_ips, capture_ip_source

    def calc_f1(self, results, ignore_unknown=False):
        results_by_label = {}
        for file, file_results in results.items():
            if file != 'labels':
                indiv_results = file_results['individual']
                true_label = file_results['label']

                if true_label not in results_by_label:
                    if true_label == 'Unknown':
                        if ignore_unknown is False:
                            results_by_label[true_label] = {
                                'tp': 0, 'fp': 0, 'fn': 0}
                    else:
                        results_by_label[true_label] = {
                            'tp': 0, 'fp': 0, 'fn': 0}

                for _, classification in indiv_results.items():
                    class_label = classification[0][0]
                    if class_label == 'Unknown' and ignore_unknown is True:
                        class_label = classification[1][0]
                    if class_label not in results_by_label:
                        results_by_label[class_label] = {
                            'tp': 0, 'fp': 0, 'fn': 0}
                    if true_label != 'Unknown':
                        if class_label == true_label:
                            results_by_label[true_label]['tp'] += 1
                        if class_label != true_label:
                            results_by_label[true_label]['fn'] += 1
                            results_by_label[class_label]['fp'] += 1
                    elif ignore_unknown is False:
                        if class_label == true_label:
                            results_by_label[true_label]['tp'] += 1
                        if class_label != true_label:
                            results_by_label[true_label]['fn'] += 1
                            results_by_label[class_label]['fp'] += 1
        f1s = []
        for label in results_by_label:
            tp = results_by_label[label]['tp']
            fp = results_by_label[label]['fp']
            fn = results_by_label[label]['fn']

            try:
                precision = tp/(tp + fp)
                recall = tp/(tp + fn)
            except Exception as e:  # pragma: no cover
                self.logger.debug(
                    'Setting precision and recall to 0 because: {0}'.format(str(e)))
                precision = 0
                recall = 0

            if precision == 0 or recall == 0:
                f1 = 0
            else:
                f1 = 2/(1/precision + 1/recall)

            if (tp + fn) > 0:
                f1s.append(f1)

            if f1 is not 'NaN':
                if (tp + fn) > 0:
                    self.logger.info('F1 of {} for {}'.format(f1, label))

        ## Check if f1s list is empty to avoid calculating mean of empty list
        if not f1s:
            self.logger.info('Mean F1: {}'.format("Empty list--no F1 scores available"))
        else:
            self.logger.info('Mean F1: {}'.format(np.mean(f1s)))

    def classify_representation(self, representation):
        '''
        Takes in a representation and produces a classification
        '''
        probabilities = []
        if self.model_type == 'randomforest':
            probabilities = self.model.predict_proba(
                representation.reshape(1, -1))
            probabilities = probabilities[0]
        elif self.model_type == 'onelayer':
            L2_weights = self.model.coefs_[1]
            L2_biases = self.model.intercepts_[1]
            probabilities = np.matmul(representation, L2_weights) + L2_biases
            probabilities = np.exp(probabilities)
            probabilities /= np.sum(probabilities)
        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(probabilities)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)

        return prediction

    def save(self, save_path):
        '''
        Saves the model to the specified file path

        Args:
            save_path: Path to store the saved model at.
        '''

        model_attributes = {
            'duration': self.duration,
            'hidden_size': self.hidden_size,
            'means': self.means,
            'stds': self.stds,
            'feature_list': self.feature_list,
            'model': self.model,
            'labels': self.labels
        }

        with open(save_path, 'wb') as handle:
            pickle.dump(model_attributes, handle)

    def load(self, load_path):
        '''
        Load the model parameters from the specified path.

        Args:
            load_path: Path to load the model parameters from
        '''

        with open(load_path, 'rb') as handle:
            model_attributes = pickle.load(handle)

        if 'duration' in model_attributes:
            self.duration = model_attributes['duration']
        else:
            self.duration = None
        if 'hidden_size' in model_attributes:
            self.hidden_size = model_attributes['hidden_size']
        else:
            self.hidden_size = None
        if 'means' in model_attributes:
            self.means = model_attributes['means']
        else:
            self.means = None
        if 'stds' in model_attributes:
            self.stds = model_attributes['stds']
        else:
            self.stds = None
        if 'feature_list' in model_attributes:
            self.feature_list = model_attributes['feature_list']
        else:
            self.feature_list = None
        if 'model' in model_attributes:
            self.model = model_attributes['model']
        else:
            self.model = None
        if 'labels' in model_attributes:
            self.labels = model_attributes['labels']
        else:
            self.labels = None
