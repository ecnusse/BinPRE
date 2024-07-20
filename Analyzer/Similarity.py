
import numpy as np

MATCH_SCORE = 1
MISMATCH_SCORE = -1
GAP_SCORE = -2

def needleman_wunsch(seq1, seq2):
    n = len(seq1)
    m = len(seq2)
    score_matrix = np.zeros((n + 1, m + 1))
    path_matrix = np.zeros((n + 1, m + 1))
    for i in range(n + 1):
        score_matrix[i][0] = i * GAP_SCORE
        path_matrix[i][0] = 2
    for j in range(m + 1):
        score_matrix[0][j] = j * GAP_SCORE
        path_matrix[0][j] = 1

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            match_score = score_matrix[i-1][j-1] + (MATCH_SCORE if seq1[i-1] == seq2[j-1] else MISMATCH_SCORE)
            delete_score = score_matrix[i-1][j] + GAP_SCORE
            insert_score = score_matrix[i][j-1] + GAP_SCORE
            score_matrix[i][j] = max(match_score, delete_score, insert_score)
            if score_matrix[i][j] == match_score:

                path_matrix[i][j] = 0
            elif score_matrix[i][j] == delete_score:
                path_matrix[i][j] = 2
            else:
                path_matrix[i][j] = 1

    i = n
    j = m
    similarity_score = 0
    while i > 0 or j > 0:
        if path_matrix[i][j] == 0:
            if seq1[i-1] == seq2[j-1]:
                similarity_score += MATCH_SCORE
            else:
                similarity_score += MISMATCH_SCORE
            i -= 1
            j -= 1
        elif path_matrix[i][j] == 2:
            similarity_score += GAP_SCORE
            i -= 1
        else:
            similarity_score += GAP_SCORE
            j -= 1
    similarity_score /= max(n, m)

    return similarity_score


