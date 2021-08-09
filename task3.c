#include <stdio.h>
#include <stdlib.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link link;
 
struct link {
    link *nextVirus;
    virus *vir;
};

virus* readVirus(FILE* file, char endian);
void printVirus(virus* virus, FILE* output);
void PrintHex(unsigned char *c,short length, FILE* output);
void list_print(link *virus_list, FILE* output);  
link* list_append(link* virus_list, virus* data); 
void list_free(link *virus_list);
void detect_virus(char *buffer, unsigned int size, link *virus_list, FILE* output);
void kill_virus(char *fileName, int signitureOffset, int signitureSize);

int main(int argc, char **argv) {
    FILE* outputStream = fopen("output","w");
    link* virus_list = (link*)malloc(sizeof(struct link));
    FILE* readFrom = NULL;

    while(1){
        printf("%s","1) Load signatures\n");
        printf("%s","2) Print signatures\n");
        printf("%s","3) Detect viruses\n");
        printf("%s","4) Fix file\n");
        int input = fgetc(stdin) - '0';
        fgetc(stdin);
        if(input == 1){ // load 
            printf("%s", "Please enter file name:\n");
            char fileName[30];
            scanf("%s",fileName);
            fgetc(stdin);
            readFrom = fopen(fileName,"r");
            char endian[4];
            fread(endian,1,4,readFrom);
            while(!feof(readFrom)){
                virus* myVirus = readVirus(readFrom,endian[3]);
                if(feof(readFrom)){
                    free(myVirus->sig);
                    free(myVirus);
                }
                else{
                    list_append(virus_list,myVirus); // each time we add to the begining
                }

            }

        }
        else if(input == 2){ // print
            list_print(virus_list,outputStream);
        }
        else if(input == 3){ // detect
            long lsize;
            char *test = argv[1];
            FILE* detectFrom = fopen(test,"r+");
            fseek(detectFrom, 0, SEEK_END);
            lsize = ftell(detectFrom);
            fseek(detectFrom, 0, SEEK_SET);
            char *buffer = (char*)(malloc(10000*sizeof(char)));
            fread(buffer,sizeof(char),lsize,detectFrom);
            detect_virus(buffer,lsize,virus_list,outputStream); // is there an option that lsize will be bigger than buffer?
        }
        else if(input == 4){
            char byteLoc[30];
            char byteSize[30];
            printf("%s", "Please enter byte location:\n");
            scanf("%s",byteLoc);
            printf("%s", "Please enter signature size:\n");
            scanf("%s", byteSize);
            fgetc(stdin);
            int location = atoi(byteLoc);
            int size = atoi(byteSize);
            kill_virus(argv[1],location,size);
        }
        else{ // not within bounds
            printf("not within bounds\n");
            if(virus_list != NULL){
                list_free(virus_list);
            }
            exit(0);
        }
    }
    return 0;
}

virus* readVirus(FILE* viruses, char endian){
    fseek(viruses, 0, SEEK_CUR);
    virus* currVirus = (virus*) malloc(sizeof(struct virus));
    fread(currVirus, 1, 18, viruses);
    if(endian == 'B'){
        currVirus->SigSize = (currVirus->SigSize>>8) | (currVirus->SigSize<<8);
    }
    currVirus->sig = (unsigned char*)malloc(currVirus->SigSize*sizeof(unsigned char));
    fread(currVirus->sig, 1, currVirus->SigSize, viruses);
    return currVirus;
} 

void printVirus(virus* myVirus, FILE* output){
    fprintf(output,"%s%s\n","Virus name: ", myVirus->virusName);
    fprintf(output,"%s%d\n","Virus size: " , myVirus->SigSize);
    fprintf(output,"%s\n","signature:");
    PrintHex(myVirus->sig,myVirus->SigSize,output);
}

void PrintHex(unsigned char *c,short length, FILE* output){
    long i = 0;
    while(i<length){
        fprintf(output,"%X\t",c[i]);
        i++;
    }
    fprintf(output,"\n");
}

link* list_append(link* virus_list, virus* data){
    if(virus_list->vir==NULL){
        virus_list->vir = data;
        virus_list->nextVirus = NULL;
        return virus_list;
    }
    else{
        link *currLink = (link*)malloc(sizeof(struct link));
        currLink->vir = data;
        currLink->nextVirus = NULL;
        while(virus_list->nextVirus != NULL){
            virus_list = virus_list->nextVirus;
        }
        virus_list->nextVirus = currLink;
        return currLink;
    }

}

void list_print(link *virus_list, FILE* output){
    while(virus_list!=NULL){
        printVirus(virus_list->vir,output);
        virus_list = virus_list->nextVirus;
    }
}

void list_free(link *virus_list){
    while(virus_list!=NULL){
        link *nextLink = virus_list->nextVirus;
        free((virus_list->vir)->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = nextLink;
    }
}

void detect_virus(char *buffer, unsigned int size, link *virus_list, FILE* output){

    while(virus_list != NULL){
        int i = 0;
        while(i < size){
            if(memcmp(virus_list->vir->sig, &buffer[i],virus_list->vir->SigSize)==0){
                fprintf(output,"%s%d\n","The loaction of the first byte: ",i);
                fprintf(output,"%s%s\n","The name of the virus: " ,virus_list->vir->virusName);
                fprintf(output,"%s%d\n","The signature size: " ,virus_list->vir->SigSize);
            }
            i++;
        }
        virus_list = virus_list->nextVirus;
    }
}

void kill_virus(char *fileName, int signitureOffset, int signitureSize){
    FILE *readFrom = fopen(fileName,"r+");
    fseek(readFrom,signitureOffset,SEEK_SET);
    char nop[signitureSize];
    int i = 0;
    while(i < signitureSize){
        nop[i] = 0x90;
        i++;
    }
    fwrite(nop,1,signitureSize,readFrom);
}




