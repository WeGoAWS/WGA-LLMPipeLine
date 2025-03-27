from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import CharacterTextSplitter

def build_and_save_vectorstore(file_path="actions.txt", save_path="faiss_index"):
    loader = TextLoader(file_path)
    docs = loader.load()
    splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    splitted_docs = splitter.split_documents(docs)

    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vectorstore = FAISS.from_documents(splitted_docs, embeddings)
    vectorstore.save_local(save_path)
    
build_and_save_vectorstore()